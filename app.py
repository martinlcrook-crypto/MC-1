from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, redirect, request, send_from_directory, session as flask_session
import requests

from history_store import init_history_db, query_history, record_snapshot
from nac_rejects import collect_nac_server_rejects, format_mac, normalize_mac
from client_lookup import get_wifi_client_detail, search_wifi_clients
from traffic_stats import MistRateLimitError, collect_traffic_usage, parse_local_datetime_to_epoch


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def load_or_create_secret_key(base_dir: Path) -> str:
    env_key = os.getenv("FLASK_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    secret_file = base_dir / ".flask_secret"
    try:
        if secret_file.exists():
            stored = secret_file.read_text(encoding="utf-8").strip()
            if stored:
                return stored
        generated = secrets.token_hex(32)
        secret_file.write_text(generated + "\n", encoding="utf-8")
        os.chmod(secret_file, 0o600)
        return generated
    except OSError:
        return secrets.token_hex(32)


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MIST_API_HOST = os.getenv("MIST_API_HOST", "https://api.eu.mist.com").rstrip("/")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "").strip()
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "").strip()
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "300"))
NAC_CACHE_TTL_SECONDS = int(os.getenv("NAC_CACHE_TTL_SECONDS", "600"))
ORG_META_CACHE_TTL_SECONDS = int(os.getenv("ORG_META_CACHE_TTL_SECONDS", "86400"))
SITES_CACHE_TTL_SECONDS = int(os.getenv("SITES_CACHE_TTL_SECONDS", "1800"))
TEMPLATES_CACHE_TTL_SECONDS = int(os.getenv("TEMPLATES_CACHE_TTL_SECONDS", "1800"))
SLOW_AP_CACHE_TTL_SECONDS = int(os.getenv("SLOW_AP_CACHE_TTL_SECONDS", "1800"))
VC_TEMP_CACHE_TTL_SECONDS = int(os.getenv("VC_TEMP_CACHE_TTL_SECONDS", "900"))
VC_TEMP_THRESHOLD_DEFAULT_C = float(os.getenv("VC_TEMP_THRESHOLD_C", "60"))
MIST_HOURLY_RATE_LIMIT = int(os.getenv("MIST_HOURLY_RATE_LIMIT", "5000"))
MIN_REFRESH_INTERVAL = 15
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "1").strip().lower() not in ("0", "false", "no")
SESSION_LIFETIME_HOURS = int(os.getenv("SESSION_LIFETIME_HOURS", "12"))
HTTPS_ENABLED = os.getenv("HTTPS_ENABLED", "").strip().lower() in ("1", "true", "yes")
HISTORY_DB_PATH = Path(os.getenv("HISTORY_DB_PATH", str(BASE_DIR / "history.db")))
HISTORY_SAMPLE_INTERVAL_SECONDS = max(60, int(os.getenv("HISTORY_SAMPLE_INTERVAL_SECONDS", "300")))

init_history_db(HISTORY_DB_PATH)

app = Flask(__name__, static_folder=None)
app.secret_key = load_or_create_secret_key(BASE_DIR)
app.config["SESSION_COOKIE_NAME"] = "mist_dash_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = HTTPS_ENABLED
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_LIFETIME_HOURS)

_cache_lock = threading.Lock()
_snapshot_fetch_lock = threading.Lock()
_cache_data: Optional[Dict[str, Any]] = None
_cache_timestamp: float = 0.0

_meta_cache_lock = threading.Lock()
_org_info_cache: Tuple[float, Optional[Dict[str, Any]]] = (0.0, None)
_sites_raw_cache: Tuple[float, Optional[List[Dict[str, Any]]]] = (0.0, None)
_templates_cache: Tuple[float, Optional[List[Dict[str, Any]]]] = (0.0, None)
_switch_info_map_cache: Tuple[float, Dict[str, Dict[str, Any]]] = (0.0, {})
_slow_aps_cache: Tuple[float, Optional[List[Dict[str, Any]]], str] = (0.0, None, "not_scanned")
_active_ap_sites_cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
_slow_aps_scan_lock = threading.Lock()

_vc_temps_cache: Tuple[float, Optional[List[Dict[str, Any]]], str] = (0.0, None, "not_scanned")
_vc_member_issues_cache: Tuple[float, List[Dict[str, Any]], str] = (0.0, [], "not_scanned")
_active_switch_sites_cache: Tuple[float, List[Dict[str, Any]]] = (0.0, [])
_vc_temps_scan_lock = threading.Lock()
_vc_temp_threshold_lock = threading.Lock()
_VC_TEMP_THRESHOLD_FILE = BASE_DIR / ".vc_temp_threshold"


def _load_vc_temp_threshold() -> float:
    try:
        if _VC_TEMP_THRESHOLD_FILE.exists():
            raw = float(_VC_TEMP_THRESHOLD_FILE.read_text(encoding="utf-8").strip())
            if 25.0 <= raw <= 95.0:
                return round(raw, 1)
    except Exception:
        pass
    return round(max(25.0, min(95.0, VC_TEMP_THRESHOLD_DEFAULT_C)), 1)


_vc_temp_threshold_c: float = _load_vc_temp_threshold()


def get_vc_temp_threshold_c() -> float:
    with _vc_temp_threshold_lock:
        return _vc_temp_threshold_c


def set_vc_temp_threshold_c(val: float) -> float:
    global _vc_temp_threshold_c
    clamped = round(max(25.0, min(95.0, float(val))), 1)
    with _vc_temp_threshold_lock:
        _vc_temp_threshold_c = clamped
    try:
        _VC_TEMP_THRESHOLD_FILE.write_text(f"{clamped}\n", encoding="utf-8")
    except OSError:
        pass
    return clamped


_polling_lock = threading.Lock()
_polling_paused: bool = os.getenv("POLLING_PAUSED_DEFAULT", "").strip().lower() in ("1", "true", "yes")
_polling_paused_at: Optional[float] = time.time() if _polling_paused else None
_polling_paused_by: Optional[str] = "environment" if _polling_paused else None
_polling_wake_event = threading.Event()

_quota_lock = threading.Lock()
_mist_call_timestamps: deque = deque()
_last_snapshot_call_count: int = 0

_auth_lock = threading.Lock()
_pending_2fa: Dict[str, Dict[str, Any]] = {}
_login_attempts: Dict[str, List[float]] = {}
LOGIN_RATE_WINDOW_SECONDS = 300
LOGIN_RATE_MAX_ATTEMPTS = 15
TWO_FACTOR_CHALLENGE_TTL_SECONDS = 300
TWO_FACTOR_MAX_ATTEMPTS = 5


def _is_polling_paused() -> bool:
    with _polling_lock:
        return _polling_paused


def get_polling_state() -> Dict[str, Any]:
    with _polling_lock:
        paused = _polling_paused
        paused_at = _polling_paused_at
        paused_by = _polling_paused_by
    return {
        "paused": paused,
        "status": "paused" if paused else "active",
        "paused_at": datetime.fromtimestamp(paused_at, tz=timezone.utc).isoformat() if paused_at else None,
        "paused_by": paused_by,
        "interval_seconds": HISTORY_SAMPLE_INTERVAL_SECONDS,
    }


def set_polling_paused(paused: bool, actor: Optional[str] = None) -> Dict[str, Any]:
    global _polling_paused, _polling_paused_at, _polling_paused_by
    with _polling_lock:
        _polling_paused = bool(paused)
        if _polling_paused:
            _polling_paused_at = time.time()
            _polling_paused_by = actor or "operator"
        else:
            _polling_paused_at = None
            _polling_paused_by = None
    if not paused:
        _polling_wake_event.set()
    return get_polling_state()


def _build_slow_aps_meta(active_ap_sites_count: Optional[int] = None, calls_used: Optional[int] = None) -> Dict[str, Any]:
    with _meta_cache_lock:
        ts_slow, items_slow, source = _slow_aps_cache
        _, cached_active_sites = _active_ap_sites_cache
    sites_cnt = active_ap_sites_count if active_ap_sites_count is not None else len(cached_active_sites)
    scanned = items_slow is not None and source != "not_scanned"
    now = time.time()
    age = int(max(0.0, now - ts_slow)) if scanned and ts_slow > 0 else None
    meta: Dict[str, Any] = {
        "scanned": scanned,
        "source": source if scanned else "not_scanned",
        "scanned_at": datetime.fromtimestamp(ts_slow, tz=timezone.utc).isoformat() if scanned and ts_slow > 0 else None,
        "cache_age_seconds": age,
        "active_ap_sites_count": sites_cnt,
        "estimated_calls": max(1, sites_cnt) if sites_cnt > 0 else 1,
        "cache_ttl_seconds": SLOW_AP_CACHE_TTL_SECONDS,
    }
    if calls_used is not None:
        meta["calls_used"] = calls_used
    return meta


_BAD_HW_STATUS_TOKENS = (
    "critical", "crit", "alert", "alarm", "fault", "fail", "failed",
    "red", "yellow", "warn", "warning", "overheat", "overheating", "high", "bad", "error",
)


def _parse_temp_celsius(val: Any) -> Optional[float]:
    if val is None or isinstance(val, bool):
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    if not (-20.0 <= f <= 150.0):
        return None
    return round(f, 1)


def _is_bad_hw_status(status: Any) -> bool:
    s = str(status or "").strip().lower()
    if not s or s in ("ok", "normal", "present", "good", "online", "absent", "not_present", "na", "n/a"):
        return False
    return any(tok in s for tok in _BAD_HW_STATUS_TOKENS)


def _extract_temps_from_container(container: Any, default_label: str = "Chassis") -> List[Tuple[str, float, bool]]:
    """Extract (sensor_name, celsius, status_alarm) tuples from Mist temperature lists/dicts/scalars."""
    readings: List[Tuple[str, float, bool]] = []
    if isinstance(container, list):
        for idx, entry in enumerate(container):
            if isinstance(entry, dict):
                st = str(entry.get("status") or "").strip().lower()
                if st in ("absent", "not_present", "empty"):
                    continue
                c_val = None
                for k in ("celsius", "temp", "temperature", "value", "temp_c"):
                    c_val = _parse_temp_celsius(entry.get(k))
                    if c_val is not None:
                        break
                if c_val is None or (c_val == 0.0 and not st):
                    continue
                name = str(entry.get("name") or entry.get("sensor") or entry.get("label") or f"{default_label} Sensor {idx}").strip()
                readings.append((name, c_val, _is_bad_hw_status(st)))
            else:
                c_val = _parse_temp_celsius(entry)
                if c_val is not None and c_val > 0:
                    readings.append((f"{default_label} Sensor {idx}", c_val, False))
    elif isinstance(container, dict):
        # Single sensor object or map of sensor_name -> celsius
        direct_val = None
        for k in ("celsius", "temp", "temperature", "value", "temp_c"):
            direct_val = _parse_temp_celsius(container.get(k))
            if direct_val is not None:
                break
        if direct_val is not None:
            st = str(container.get("status") or "").strip().lower()
            if st not in ("absent", "not_present", "empty"):
                name = str(container.get("name") or container.get("sensor") or default_label).strip()
                readings.append((name, direct_val, _is_bad_hw_status(st)))
        else:
            for k, v in container.items():
                if isinstance(v, (dict, list)):
                    readings.extend(_extract_temps_from_container(v, default_label=str(k)))
                else:
                    c_val = _parse_temp_celsius(v)
                    if c_val is not None and c_val > 0:
                        readings.append((str(k), c_val, False))
    else:
        c_val = _parse_temp_celsius(container)
        if c_val is not None and c_val > 0:
            readings.append((default_label, c_val, False))
    return readings


def extract_switch_thermal_info(sw: Dict[str, Any], site_name: str) -> Optional[Dict[str, Any]]:
    """Extract Virtual Chassis / switch temperature, FPC member breakdown, and fan/PSU health from Mist switch stats."""
    if not isinstance(sw, dict):
        return None
    if str(sw.get("status") or "").lower() != "connected":
        return None

    module_stat = sw.get("module_stat") if isinstance(sw.get("module_stat"), list) else []
    vc_setup = sw.get("vc_setup_info") if isinstance(sw.get("vc_setup_info"), dict) else {}
    vc_mac_raw = str(sw.get("vc_mac") or "").strip()

    all_readings: List[Tuple[str, float, bool, str, Optional[int]]] = []
    members_summary: List[Dict[str, Any]] = []
    fans_total = 0
    fans_bad = 0
    psus_total = 0
    psus_bad = 0
    has_vc_role = False

    for idx, mod in enumerate(module_stat):
        if not isinstance(mod, dict):
            continue
        fpc_raw = mod.get("fpc_idx")
        fpc_idx = int(fpc_raw) if isinstance(fpc_raw, (int, float)) else idx
        vc_role = str(mod.get("vc_role") or "").strip().lower()
        if vc_role:
            has_vc_role = True
        member_label = f"FPC {fpc_idx} ({vc_role})" if vc_role else f"FPC {fpc_idx}"

        mod_readings: List[Tuple[str, float, bool]] = []
        if "temperatures" in mod:
            mod_readings.extend(_extract_temps_from_container(mod.get("temperatures"), default_label=f"FPC {fpc_idx}"))
        if not mod_readings:
            for tk in ("temperature", "temp", "temp_c"):
                if tk in mod:
                    mod_readings.extend(_extract_temps_from_container(mod.get(tk), default_label=f"FPC {fpc_idx}"))
                    if mod_readings:
                        break

        for s_name, c_val, s_alarm in mod_readings:
            all_readings.append((s_name, c_val, s_alarm, member_label, fpc_idx))

        if mod_readings:
            hottest_m = max(mod_readings, key=lambda r: (r[1], int(r[2])))
            members_summary.append(
                {
                    "fpc_idx": fpc_idx,
                    "vc_role": vc_role or "member",
                    "model": str(mod.get("model") or sw.get("model") or ""),
                    "serial": str(mod.get("serial") or ""),
                    "peak_temp_c": hottest_m[1],
                    "hottest_sensor": hottest_m[0],
                    "sensor_alarm": any(r[2] for r in mod_readings),
                }
            )

        for fan in (mod.get("fans") if isinstance(mod.get("fans"), list) else []):
            if not isinstance(fan, dict):
                continue
            fst = str(fan.get("status") or "").strip().lower()
            if fst in ("absent", "not_present", "empty"):
                continue
            fans_total += 1
            if _is_bad_hw_status(fst):
                fans_bad += 1

        for psu in (mod.get("psus") if isinstance(mod.get("psus"), list) else []):
            if not isinstance(psu, dict):
                continue
            pst = str(psu.get("status") or "").strip().lower()
            if pst in ("absent", "not_present", "empty"):
                continue
            psus_total += 1
            if _is_bad_hw_status(pst):
                psus_bad += 1

    # Fallback top-level switch temperature fields if module_stat didn't yield any readings
    if not all_readings:
        top_readings: List[Tuple[str, float, bool]] = []
        for tk in ("temperatures", "env_stat", "temperature", "temp", "temp_c"):
            if tk in sw and sw.get(tk) is not None:
                val = sw.get(tk)
                if tk == "env_stat" and isinstance(val, dict):
                    top_readings.extend(_extract_temps_from_container(val.get("temperatures") or val, default_label="Chassis"))
                else:
                    top_readings.extend(_extract_temps_from_container(val, default_label="Chassis"))
                if top_readings:
                    break
        for s_name, c_val, s_alarm in top_readings:
            all_readings.append((s_name, c_val, s_alarm, "Chassis", 0))

    if not all_readings:
        return None

    hottest = max(all_readings, key=lambda r: (r[1], int(r[2])))
    peak_temp_c = hottest[1]
    avg_temp_c = round(sum(r[1] for r in all_readings) / len(all_readings), 1)
    sensor_status_alarm = any(r[2] for r in all_readings)

    is_vc = bool(
        len(module_stat) > 1
        or vc_mac_raw
        or bool(vc_setup)
        or has_vc_role
        or sw.get("is_vc") is True
    )
    member_count = max(len(module_stat), len(members_summary), 1)
    members_summary.sort(key=lambda m: (-m["peak_temp_c"], m["fpc_idx"]))

    ip_stat = sw.get("ip_stat") if isinstance(sw.get("ip_stat"), dict) else {}
    sw_ip = str(sw.get("ip") or ip_stat.get("ip") or "").strip()
    sw_mac = format_mac(sw.get("mac")) if sw.get("mac") else ""
    vc_mac = format_mac(vc_mac_raw) if vc_mac_raw else ""

    return {
        "id": str(sw.get("id") or sw_mac or sw.get("name") or ""),
        "name": str(sw.get("name") or sw_mac or "Unnamed Switch"),
        "site_id": str(sw.get("site_id") or ""),
        "site_name": site_name,
        "model": str(sw.get("model") or ""),
        "mac": sw_mac,
        "vc_mac": vc_mac,
        "ip": sw_ip,
        "version": str(sw.get("version") or ""),
        "is_vc": is_vc,
        "member_count": member_count,
        "peak_temp_c": peak_temp_c,
        "avg_temp_c": avg_temp_c,
        "hottest_sensor": hottest[0],
        "hottest_member": hottest[3],
        "hottest_fpc_idx": hottest[4],
        "sensor_count": len(all_readings),
        "sensor_status_alarm": sensor_status_alarm,
        "fans_total": fans_total,
        "fans_bad": fans_bad,
        "psus_total": psus_total,
        "psus_bad": psus_bad,
        "members": members_summary,
        "last_seen": sw.get("last_seen"),
    }


def _build_vc_temps_view(
    raw_items: Optional[List[Dict[str, Any]]],
    active_switch_sites_count: Optional[int] = None,
    calls_used: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Annotate cached thermal switch/VC items against the active threshold and compute summary metadata."""
    threshold_c = get_vc_temp_threshold_c()
    warn_c = round(max(20.0, threshold_c - 5.0), 1)
    with _meta_cache_lock:
        ts_vc, cached_items, source = _vc_temps_cache
        _, cached_sw_sites = _active_switch_sites_cache
    items_src = raw_items if raw_items is not None else (cached_items or [])
    sites_cnt = active_switch_sites_count if active_switch_sites_count is not None else len(cached_sw_sites)
    scanned = (raw_items is not None) or (cached_items is not None and source != "not_scanned")

    evaluated: List[Dict[str, Any]] = []
    for item in items_src:
        rec = dict(item)
        peak = float(rec.get("peak_temp_c") or 0.0)
        sensor_alarm = bool(rec.get("sensor_status_alarm"))
        above_thresh = (peak >= threshold_c) or sensor_alarm
        if above_thresh:
            alarm_state = "alarm"
        elif peak >= warn_c:
            alarm_state = "warn"
        else:
            alarm_state = "ok"
        rec["above_threshold"] = above_thresh
        rec["alarm_state"] = alarm_state
        rec["delta_threshold_c"] = round(peak - threshold_c, 1)
        rec["threshold_c"] = threshold_c
        evaluated.append(rec)

    evaluated.sort(key=lambda x: (-float(x.get("peak_temp_c") or 0.0), -int(bool(x.get("is_vc"))), str(x.get("name") or "").lower()))

    vc_only = [x for x in evaluated if x.get("is_vc")]
    primary_list = vc_only if vc_only else evaluated
    alarmed_vcs = [x for x in vc_only if x.get("above_threshold")]
    alarmed_all = [x for x in evaluated if x.get("above_threshold")]
    max_temp = primary_list[0]["peak_temp_c"] if primary_list else None
    avg_temp = round(sum(float(x["peak_temp_c"]) for x in primary_list) / len(primary_list), 1) if primary_list else None
    hw_faults = sum(int(x.get("fans_bad") or 0) + int(x.get("psus_bad") or 0) for x in primary_list)

    now = time.time()
    age = int(max(0.0, now - ts_vc)) if scanned and ts_vc > 0 else None
    meta: Dict[str, Any] = {
        "scanned": scanned,
        "source": source if scanned else "not_scanned",
        "scanned_at": datetime.fromtimestamp(ts_vc, tz=timezone.utc).isoformat() if scanned and ts_vc > 0 else None,
        "cache_age_seconds": age,
        "threshold_c": threshold_c,
        "warn_c": warn_c,
        "vc_count": len(vc_only),
        "switch_count": len(evaluated),
        "alarmed_vcs_count": len(alarmed_vcs),
        "alarmed_all_count": len(alarmed_all),
        "alarmed_count": len(alarmed_vcs) if vc_only else len(alarmed_all),
        "max_temp_c": max_temp,
        "avg_temp_c": avg_temp,
        "hw_faults_count": hw_faults,
        "active_switch_sites_count": sites_cnt,
        "estimated_calls": max(1, sites_cnt) if sites_cnt > 0 else 1,
        "cache_ttl_seconds": VC_TEMP_CACHE_TTL_SECONDS,
    }
    if calls_used is not None:
        meta["calls_used"] = calls_used
    return evaluated, meta


_VC_DOWN_STATE_TOKENS = (
    "notpresent", "not_present", "not-present", "not present",
    "inactive", "offline", "absent", "down", "disconnected",
    "unprovisioned", "dead", "fault", "failed", "error",
    "wedge", "wedged", "unresponsive", "panic", "resetting",
)
_VC_HEALTHY_STATE_TOKENS = ("present", "prsnt", "online", "ok", "ready", "up", "active", "normal")
_FPC_PFE_TOKEN_RE = re.compile(r"\b(?:FPC|PFE|PIC|Linecard)\s*[-:#]?\s*\d+\b", re.IGNORECASE)


def _is_down_member_state(raw_state: Any) -> bool:
    s = str(raw_state or "").strip().lower()
    if not s or s in _VC_HEALTHY_STATE_TOKENS:
        return False
    return any(tok in s for tok in _VC_DOWN_STATE_TOKENS)


def _extract_pfe_faults_from_obj(container: Any, default_prefix: str = "PFE") -> List[Tuple[str, str]]:
    """Return list of (pfe_label, state_str) for any PFE reporting down/offline/fault."""
    faults: List[Tuple[str, str]] = []
    if isinstance(container, list):
        for idx, entry in enumerate(container):
            if isinstance(entry, dict):
                label = str(entry.get("name") or entry.get("id") or entry.get("pfe") or f"{default_prefix} {entry.get('index', idx)}").strip()
                if entry.get("up") is False or entry.get("online") is False:
                    st = str(entry.get("status") or entry.get("state") or "offline").strip()
                    faults.append((label, st or "offline"))
                    continue
                for sk in ("status", "state", "pfe_status", "pfe_state"):
                    st_val = entry.get(sk)
                    if _is_down_member_state(st_val):
                        faults.append((label, str(st_val).strip()))
                        break
            elif _is_down_member_state(entry):
                faults.append((f"{default_prefix} {idx}", str(entry).strip()))
    elif isinstance(container, dict):
        if container.get("up") is False or container.get("online") is False:
            st = str(container.get("status") or container.get("state") or "offline").strip()
            faults.append((default_prefix, st or "offline"))
        else:
            direct_bad = False
            for sk in ("status", "state", "pfe_status", "pfe_state"):
                st_val = container.get(sk)
                if _is_down_member_state(st_val):
                    faults.append((str(container.get("name") or default_prefix), str(st_val).strip()))
                    direct_bad = True
                    break
            if not direct_bad:
                for k, v in container.items():
                    if isinstance(v, (dict, list)):
                        faults.extend(_extract_pfe_faults_from_obj(v, default_prefix=str(k)))
                    elif _is_down_member_state(v):
                        faults.append((str(k), str(v).strip()))
    elif _is_down_member_state(container):
        faults.append((default_prefix, str(container).strip()))
    return faults


def extract_vc_member_issues(sw: Dict[str, Any], site_name: str) -> List[Dict[str, Any]]:
    """Detect down VC members, offline linecards, missing provisioned FPCs, and down PFEs on a connected switch/VC."""
    if not isinstance(sw, dict):
        return []
    if str(sw.get("status") or "").lower() != "connected":
        return []

    module_stat = sw.get("module_stat") if isinstance(sw.get("module_stat"), list) else []
    vc_setup = sw.get("vc_setup_info") if isinstance(sw.get("vc_setup_info"), dict) else {}
    vc_members = sw.get("vc_members") if isinstance(sw.get("vc_members"), list) else []
    vc_mac_raw = str(sw.get("vc_mac") or "").strip()

    is_vc = bool(
        len(module_stat) > 1
        or vc_mac_raw
        or bool(vc_setup)
        or len(vc_members) > 1
        or any(isinstance(m, dict) and str(m.get("vc_role") or "").strip() for m in module_stat)
        or sw.get("is_vc") is True
    )

    ip_stat = sw.get("ip_stat") if isinstance(sw.get("ip_stat"), dict) else {}
    sw_ip = str(sw.get("ip") or ip_stat.get("ip") or "").strip()
    sw_mac = format_mac(sw.get("mac")) if sw.get("mac") else ""
    vc_mac = format_mac(vc_mac_raw) if vc_mac_raw else ""
    sw_name = str(sw.get("name") or sw_mac or "Unnamed Switch")
    sw_model = str(sw.get("model") or "")
    sw_last_seen = sw.get("last_seen")

    issues: List[Dict[str, Any]] = []
    present_fpcs = set()
    flagged_fpcs = set()

    def add_issue(
        member_label: str,
        issue_type: str,
        state: str,
        details: str,
        fpc_idx: Optional[int] = None,
        member_model: str = "",
        member_serial: str = "",
        source: str = "Switch Telemetry",
    ) -> None:
        issues.append(
            {
                "switch_name": sw_name,
                "site_id": str(sw.get("site_id") or ""),
                "site_name": site_name,
                "model": member_model or sw_model,
                "mac": vc_mac or sw_mac,
                "ip": sw_ip,
                "is_vc": is_vc,
                "member_count": max(len(module_stat), len(vc_members), 1),
                "fpc_idx": fpc_idx,
                "member_label": member_label,
                "serial": member_serial,
                "issue_type": issue_type,
                "state": state,
                "details": details,
                "source": source,
                "timestamp": sw_last_seen or int(time.time()),
            }
        )

    # 1. Inspect every FPC member in module_stat
    for idx, mod in enumerate(module_stat):
        if not isinstance(mod, dict):
            continue
        fpc_raw = mod.get("fpc_idx")
        fpc_idx = int(fpc_raw) if isinstance(fpc_raw, (int, float)) else idx
        vc_role = str(mod.get("vc_role") or "").strip().lower()
        vc_state = str(mod.get("vc_state") or "").strip()
        mod_status = str(mod.get("status") or mod.get("state") or mod.get("fpc_state") or "").strip()
        member_label = f"FPC {fpc_idx} ({vc_role})" if vc_role else f"FPC {fpc_idx}"
        m_model = str(mod.get("model") or sw_model)
        m_serial = str(mod.get("serial") or "")

        member_down = False
        if _is_down_member_state(vc_state):
            member_down = True
            flagged_fpcs.add(fpc_idx)
            itype = "Linecard Offline" if vc_role == "linecard" else "VC Member Down"
            add_issue(
                member_label=member_label,
                issue_type=itype,
                state=vc_state,
                details=f"vc_state={vc_state}" + (f" · serial {m_serial}" if m_serial else ""),
                fpc_idx=fpc_idx,
                member_model=m_model,
                member_serial=m_serial,
            )
        elif _is_down_member_state(mod_status):
            member_down = True
            flagged_fpcs.add(fpc_idx)
            itype = "Linecard Offline" if vc_role == "linecard" else "VC Member Down"
            add_issue(
                member_label=member_label,
                issue_type=itype,
                state=mod_status,
                details=f"module status={mod_status}" + (f" · serial {m_serial}" if m_serial else ""),
                fpc_idx=fpc_idx,
                member_model=m_model,
                member_serial=m_serial,
            )
        else:
            present_fpcs.add(fpc_idx)

        # 2. Inspect PFEs on this member (even when vc_state is still "present"!)
        for pk in ("pfes", "pfe_stat", "pfe_status", "pfe", "fpc_pfe", "asic_stat"):
            if pk in mod and mod.get(pk) is not None:
                for pfe_lbl, pfe_st in _extract_pfe_faults_from_obj(mod.get(pk), default_prefix="PFE"):
                    add_issue(
                        member_label=f"{member_label} · {pfe_lbl}",
                        issue_type="PFE Down",
                        state=pfe_st,
                        details=f"PFE {pfe_st} on {member_label} (vc_state={vc_state or 'present'})",
                        fpc_idx=fpc_idx,
                        member_model=m_model,
                        member_serial=m_serial,
                    )

        # 3. Inspect PICs on this member (ignore normal empty uplink slots that are merely 'absent'/'empty')
        if not member_down and isinstance(mod.get("pics"), list):
            for p_idx, pic in enumerate(mod["pics"]):
                if not isinstance(pic, dict):
                    continue
                p_st = str(pic.get("status") or pic.get("state") or "").strip().lower()
                if p_st in ("offline", "down", "dead", "fault", "failed", "error", "inactive", "wedged"):
                    pic_num = pic.get("index", p_idx)
                    pic_model = str(pic.get("model_number") or pic.get("model") or "").strip()
                    add_issue(
                        member_label=f"{member_label} · PIC {pic_num}",
                        issue_type="PFE / PIC Down",
                        state=p_st,
                        details=f"PIC {pic_num} {p_st}" + (f" ({pic_model})" if pic_model else ""),
                        fpc_idx=fpc_idx,
                        member_model=m_model,
                        member_serial=m_serial,
                    )

    # 4. Top-level PFE telemetry (some Juniper switch models expose pfe_stat at switch root)
    for pk in ("pfes", "pfe_stat", "pfe_status"):
        if pk in sw and sw.get(pk) is not None:
            for pfe_lbl, pfe_st in _extract_pfe_faults_from_obj(sw.get(pk), default_prefix="PFE"):
                add_issue(
                    member_label=pfe_lbl,
                    issue_type="PFE Down",
                    state=pfe_st,
                    details=f"Switch PFE reports {pfe_st}",
                )

    # 5. Preprovisioned VC missing members via vc_setup_info / vc_members
    if vc_setup:
        missing_fpc = vc_setup.get("err_missing_dev_id_fpc")
        if missing_fpc:
            if isinstance(missing_fpc, list):
                for mf in missing_fpc:
                    try:
                        mf_idx = int(mf)
                    except (TypeError, ValueError):
                        mf_idx = None
                    if mf_idx is not None and mf_idx in flagged_fpcs:
                        continue
                    add_issue(
                        member_label=f"FPC {mf}" if mf_idx is not None else str(mf),
                        issue_type="Missing VC Member",
                        state="missing",
                        details="Preprovisioned FPC member missing from active Virtual Chassis",
                        fpc_idx=mf_idx,
                    )
            else:
                add_issue(
                    member_label="Provisioned FPC",
                    issue_type="Missing VC Member",
                    state="missing",
                    details="vc_setup_info reports missing preprovisioned FPC member",
                )

        setup_members = vc_setup.get("members") if isinstance(vc_setup.get("members"), list) else []
        for sm in setup_members:
            if not isinstance(sm, dict):
                continue
            f_raw = sm.get("fpc_idx") if sm.get("fpc_idx") is not None else sm.get("member_id")
            f_idx = int(f_raw) if isinstance(f_raw, (int, float)) else None
            sm_state = str(sm.get("vc_state") or sm.get("state") or sm.get("status") or "").strip()
            sm_role = str(sm.get("vc_role") or sm.get("role") or "").strip().lower()
            if f_idx is not None and f_idx in flagged_fpcs:
                continue
            if _is_down_member_state(sm_state) or (f_idx is not None and present_fpcs and f_idx not in present_fpcs):
                lbl = f"FPC {f_idx} ({sm_role})" if (f_idx is not None and sm_role) else (f"FPC {f_idx}" if f_idx is not None else "VC Member")
                add_issue(
                    member_label=lbl,
                    issue_type="Linecard Offline" if sm_role == "linecard" else "VC Member Down",
                    state=sm_state or "notpresent",
                    details=f"Configured VC member offline/missing ({sm_state or 'not present in module_stat'})",
                    fpc_idx=f_idx,
                    member_serial=str(sm.get("serial") or ""),
                )

    for vm in vc_members:
        if not isinstance(vm, dict):
            continue
        f_raw = vm.get("fpc_idx") if vm.get("fpc_idx") is not None else vm.get("member_id")
        f_idx = int(f_raw) if isinstance(f_raw, (int, float)) else None
        if f_idx is not None and f_idx in flagged_fpcs:
            continue
        vm_state = str(vm.get("vc_state") or vm.get("state") or vm.get("status") or "").strip()
        vm_role = str(vm.get("vc_role") or vm.get("role") or "").strip().lower()
        if _is_down_member_state(vm_state):
            lbl = f"FPC {f_idx} ({vm_role})" if (f_idx is not None and vm_role) else (f"FPC {f_idx}" if f_idx is not None else "VC Member")
            add_issue(
                member_label=lbl,
                issue_type="Linecard Offline" if vm_role == "linecard" else "VC Member Down",
                state=vm_state,
                details=f"vc_members state={vm_state}",
                fpc_idx=f_idx,
                member_serial=str(vm.get("serial") or ""),
            )

    return issues


def extract_vc_alarm_issues(
    raw_alarms: List[Dict[str, Any]],
    site_map: Dict[str, Dict[str, Any]],
    switch_info_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Surface active/unacknowledged Mist org alarms indicating down VC members, offline linecards, or down PFEs."""
    results: List[Dict[str, Any]] = []
    vc_keywords = ("pfe", "fpc", "linecard", "line card", "vc_member", "vc member", "virtual chassis", "vcp")
    fault_keywords = ("down", "offline", "not present", "notpresent", "dead", "fail", "fault", "wedge", "missing", "inactive", "disconnect", "panic", "unreachable")
    recovery_phrases = ("came up", "is up", "back online", "restored", "recovered", "reconnected")

    for a in raw_alarms or []:
        if not isinstance(a, dict):
            continue
        if a.get("acked") is True or a.get("resolved") is True:
            continue
        a_type = str(a.get("type") or "").strip()
        a_text = str(a.get("text") or "").strip()
        combined = f"{a_type} {a_text}".lower()
        if not any(k in combined for k in vc_keywords):
            continue
        if not any(k in combined for k in fault_keywords):
            continue
        if any(rp in combined for rp in recovery_phrases):
            continue

        sid = str(a.get("site_id") or "")
        site_name = a.get("site_name") or site_map.get(sid, {}).get("name", "Org")

        hostnames = a.get("hostnames") if isinstance(a.get("hostnames"), list) else []
        sw_list = a.get("switches") if isinstance(a.get("switches"), list) else []
        mac_raw = a.get("mac") or a.get("device_mac") or (sw_list[0] if sw_list else "")
        smac = normalize_mac(mac_raw)
        sw_info = switch_info_map.get(smac, {}) if smac else {}
        sw_name = (
            (str(hostnames[0]).strip() if hostnames else "")
            or str(a.get("device_name") or a.get("switch_name") or "").strip()
            or sw_info.get("name")
            or (format_mac(smac) if smac else "Virtual Chassis")
        )
        tokens = _FPC_PFE_TOKEN_RE.findall(a_text or a_type)
        member_label = " · ".join(dict.fromkeys(t.upper() for t in tokens)) if tokens else "VC Member / PFE"
        is_pfe = "pfe" in combined
        issue_type = "PFE Down" if is_pfe else ("Linecard Offline" if "linecard" in combined or "line card" in combined else "VC Member Down")
        results.append(
            {
                "switch_name": sw_name,
                "site_id": sid,
                "site_name": site_name,
                "model": sw_info.get("model", ""),
                "mac": format_mac(smac) if smac else "",
                "ip": sw_info.get("ip", ""),
                "is_vc": True,
                "member_count": 0,
                "fpc_idx": None,
                "member_label": member_label,
                "serial": "",
                "issue_type": issue_type,
                "state": str(a.get("severity") or "alarm").lower(),
                "details": a_text or a_type.replace("_", " "),
                "source": "Mist Alarm",
                "timestamp": a.get("last_seen") or a.get("timestamp") or int(time.time()),
            }
        )
    return results


def _merge_vc_member_issues(
    telemetry_issues: List[Dict[str, Any]],
    alarm_issues: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Deduplicate switch telemetry VC/PFE issues with Mist org alarm issues."""
    merged: List[Dict[str, Any]] = []
    seen = set()
    for item in list(telemetry_issues) + list(alarm_issues):
        raw_lbl = str(item.get("member_label") or "").strip().lower()
        norm_lbl = re.sub(r"\s*\([^)]*\)", "", raw_lbl)
        norm_lbl = re.sub(r"\s+", " ", norm_lbl).strip()
        key = (
            str(item.get("switch_name") or "").strip().lower(),
            norm_lbl,
            str(item.get("issue_type") or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    merged.sort(key=lambda x: (0 if "PFE" in str(x.get("issue_type")) else 1, str(x.get("site_name") or "").lower(), str(x.get("switch_name") or "").lower(), str(x.get("member_label") or "")))
    return merged


def _record_mist_api_call() -> None:
    now = time.time()
    cutoff = now - 3600.0
    with _quota_lock:
        _mist_call_timestamps.append(now)
        while _mist_call_timestamps and _mist_call_timestamps[0] < cutoff:
            _mist_call_timestamps.popleft()


def get_mist_api_quota_snapshot() -> Dict[str, Any]:
    now = time.time()
    cutoff = now - 3600.0
    with _quota_lock:
        while _mist_call_timestamps and _mist_call_timestamps[0] < cutoff:
            _mist_call_timestamps.popleft()
        calls_1h = len(_mist_call_timestamps)
        last_snap = _last_snapshot_call_count
    pct = round((calls_1h / MIST_HOURLY_RATE_LIMIT) * 100.0, 1) if MIST_HOURLY_RATE_LIMIT > 0 else 0.0
    return {
        "calls_last_hour": calls_1h,
        "hourly_limit": MIST_HOURLY_RATE_LIMIT,
        "pct_used": pct,
        "last_snapshot_calls": last_snap,
    }


class TrackedMistSession(requests.Session):
    """requests.Session subclass that counts every outbound Mist API call against the 1h rolling quota."""

    def __init__(self) -> None:
        super().__init__()
        self.call_count = 0
        self._count_lock = threading.Lock()

    def request(self, method: Any, url: Any, *args: Any, **kwargs: Any) -> requests.Response:
        _record_mist_api_call()
        with self._count_lock:
            self.call_count += 1
        return super().request(method, url, *args, **kwargs)


def _new_mist_session() -> TrackedMistSession:
    session = TrackedMistSession()
    session.headers.update(
        {
            "Authorization": f"Token {MIST_API_TOKEN}",
            "Accept": "application/json",
        }
    )
    return session


def mist_get_raw(
    session: requests.Session, path: str, params: Optional[Dict[str, Any]] = None
) -> Tuple[Any, Any]:
    """Strictly read-only GET helper returning (parsed JSON, response headers)."""
    url = f"{MIST_API_HOST}{path}"
    resp = session.get(url, params=params, timeout=20)
    if resp.status_code == 429:
        raise MistRateLimitError(
            "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
        )
    resp.raise_for_status()
    return resp.json(), resp.headers


def mist_get(session: requests.Session, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Strictly read-only GET helper for the Juniper Mist API."""
    data, _ = mist_get_raw(session, path, params=params)
    return data


def _extract_item_key(item: Any, dedup_keys: Tuple[str, ...]) -> Optional[str]:
    if not isinstance(item, dict):
        return None
    for key in dedup_keys:
        val = item.get(key)
        if val is not None:
            norm = str(val).strip().lower()
            if norm:
                return f"{key}:{norm}"
    return None


def _parse_page_headers(headers: Any) -> Optional[Tuple[int, int, int]]:
    if not headers:
        return None
    total_raw = headers.get("X-Page-Total")
    limit_raw = headers.get("X-Page-Limit")
    page_raw = headers.get("X-Page-Page")
    if total_raw is None or limit_raw is None or page_raw is None:
        return None
    try:
        total = int(total_raw)
        page_limit = int(limit_raw)
        page = int(page_raw)
    except (TypeError, ValueError):
        return None
    if total < 0 or page_limit <= 0 or page < 1:
        return None
    return total, page_limit, page


def _item_last_seen(item: Dict[str, Any]) -> float:
    raw = item.get("last_seen")
    return float(raw) if isinstance(raw, (int, float)) else 0.0


def mist_get_paginated(
    session: requests.Session,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    limit: int = 1000,
    max_pages: int = 50,
    send_page_params: bool = True,
    dedup_keys: Tuple[str, ...] = ("mac", "id"),
) -> List[Dict[str, Any]]:
    """Fetch Mist list endpoints safely without duplicating unpaginated responses."""
    items: List[Dict[str, Any]] = []
    key_to_index: Dict[str, int] = {}
    base_params = dict(params or {})
    effective_limit = limit

    for page in range(1, max_pages + 1):
        req_params = dict(base_params)
        if send_page_params:
            req_params.setdefault("limit", effective_limit)
            req_params["page"] = page
        elif page > 1:
            req_params.setdefault("limit", effective_limit)
            req_params["page"] = page

        data, headers = mist_get_raw(session, path, params=req_params)
        if not isinstance(data, list) or not data:
            break

        new_unique_count = 0
        for entry in data:
            if not isinstance(entry, dict):
                continue
            item_key = _extract_item_key(entry, dedup_keys)
            if item_key is None:
                items.append(entry)
                new_unique_count += 1
            elif item_key not in key_to_index:
                key_to_index[item_key] = len(items)
                items.append(entry)
                new_unique_count += 1
            else:
                idx = key_to_index[item_key]
                if _item_last_seen(entry) > _item_last_seen(items[idx]):
                    items[idx] = entry

        # If a subsequent page returned only duplicates, the endpoint ignored `page`
        if page > 1 and new_unique_count == 0:
            break

        page_meta = _parse_page_headers(headers)
        if page_meta is not None:
            total, page_limit, current_page = page_meta
            effective_limit = page_limit
            if current_page * page_limit >= total or len(items) >= total:
                break
        else:
            # No Mist X-Page-* pagination headers: stop immediately for unpaginated endpoints,
            # or when len(data) != requested limit (covers both short final pages and endpoints
            # that ignore `limit` and return the entire list at once).
            if not send_page_params or len(data) != int(req_params.get("limit", effective_limit)):
                break

    return items


def normalize_band(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val.startswith("24") or val == "2.4":
        return "2.4 GHz"
    if val.startswith("5"):
        return "5 GHz"
    if val.startswith("6"):
        return "6 GHz"
    return "Other"


def normalize_proto(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val == "be":
        return "Wi-Fi 7 (be)"
    if val == "ax":
        return "Wi-Fi 6/6E (ax)"
    if val == "ac":
        return "Wi-Fi 5 (ac)"
    if val in ("n", "a", "g", "b"):
        return f"Legacy ({val})"
    return "Other"


def extract_ap_uplink_info(ap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return any active Ethernet ports on the AP negotiated below 1000 Mbps (1 Gbps)."""
    port_stat = ap.get("port_stat")
    if not isinstance(port_stat, dict) or not port_stat:
        return []

    lldp_top = ap.get("lldp_stat") if isinstance(ap.get("lldp_stat"), dict) else {}
    lldp_map = ap.get("lldp_stats") if isinstance(ap.get("lldp_stats"), dict) else {}

    degraded_ports: List[Dict[str, Any]] = []
    # Check eth0 first, then any other ethernet ports in deterministic order
    port_names = sorted(port_stat.keys(), key=lambda k: (0 if k == "eth0" else 1, k))

    for port_name in port_names:
        pstat = port_stat.get(port_name)
        if not isinstance(pstat, dict):
            continue

        is_up = pstat.get("up")
        raw_speed = pstat.get("speed")
        speed = int(raw_speed) if isinstance(raw_speed, (int, float)) else 0

        # Only evaluate ports that are up and report a negotiated link speed
        if is_up is False or speed <= 0:
            continue

        full_duplex = pstat.get("full_duplex")
        # Flag any port negotiated below 1000 Mbps (e.g. 10/100 Mbps) or half-duplex
        if speed < 1000 or full_duplex is False:
            port_lldp = lldp_map.get(port_name) if isinstance(lldp_map.get(port_name), dict) else {}
            if not port_lldp and "system_name" in lldp_map:
                port_lldp = lldp_map
            lldp = {**lldp_top, **port_lldp}

            switch_name = (
                str(lldp.get("system_name") or "").strip()
                or str(lldp.get("chassis_id") or "").strip()
                or "Unknown Switch"
            )
            switch_port = (
                str(lldp.get("port_id") or "").strip()
                or str(lldp.get("port_desc") or "").strip()
                or "Unknown Port"
            )
            switch_port_desc = str(lldp.get("port_desc") or "").strip()
            mgmt_addrs = lldp.get("mgmt_addrs")
            switch_ip = str(lldp.get("mgmt_addr") or "").strip()
            if not switch_ip and isinstance(mgmt_addrs, list) and mgmt_addrs:
                switch_ip = str(mgmt_addrs[0] or "").strip()

            if full_duplex is True:
                duplex_label = "Full"
            elif full_duplex is False:
                duplex_label = "Half"
            else:
                duplex_label = "Auto"

            degraded_ports.append(
                {
                    "ap_port": port_name,
                    "speed": speed,
                    "speed_label": f"{speed} Mbps" if speed < 1000 else f"{speed // 1000} Gbps",
                    "full_duplex": full_duplex,
                    "duplex": duplex_label,
                    "rx_errors": int(pstat.get("rx_errors") or 0),
                    "switch_name": switch_name,
                    "switch_port": switch_port,
                    "switch_port_desc": switch_port_desc if switch_port_desc != switch_port else "",
                    "switch_ip": switch_ip,
                }
            )

    return degraded_ports


def _get_org_info_cached(session: requests.Session) -> Dict[str, Any]:
    global _org_info_cache
    now = time.time()
    with _meta_cache_lock:
        ts, cached = _org_info_cache
        if cached is not None and (now - ts) < ORG_META_CACHE_TTL_SECONDS:
            return cached
    info = mist_get(session, f"/api/v1/orgs/{MIST_ORG_ID}")
    if isinstance(info, dict):
        with _meta_cache_lock:
            _org_info_cache = (time.time(), info)
        return info
    return {}


def _get_sites_raw_cached(session: requests.Session) -> List[Dict[str, Any]]:
    global _sites_raw_cache
    now = time.time()
    with _meta_cache_lock:
        ts, cached = _sites_raw_cache
        if cached is not None and (now - ts) < SITES_CACHE_TTL_SECONDS:
            return cached
    sites_raw = mist_get_paginated(
        session,
        f"/api/v1/orgs/{MIST_ORG_ID}/sites",
        limit=1000,
        send_page_params=True,
        dedup_keys=("id",),
    )
    with _meta_cache_lock:
        _sites_raw_cache = (time.time(), sites_raw)
    return sites_raw


def _get_network_templates_cached(session: requests.Session) -> List[Dict[str, Any]]:
    global _templates_cache
    now = time.time()
    with _meta_cache_lock:
        ts, cached = _templates_cache
        if cached is not None and (now - ts) < TEMPLATES_CACHE_TTL_SECONDS:
            return cached
    resp = session.get(f"{MIST_API_HOST}/api/v1/orgs/{MIST_ORG_ID}/networktemplates", timeout=20)
    if resp.status_code == 429:
        raise MistRateLimitError(
            "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
        )
    if resp.status_code in (403, 404):
        templates: List[Dict[str, Any]] = []
    else:
        resp.raise_for_status()
        data = resp.json()
        templates = data if isinstance(data, list) else []
    with _meta_cache_lock:
        _templates_cache = (time.time(), templates)
    return templates


def _cached_switch_info_map() -> Optional[Dict[str, Dict[str, Any]]]:
    now = time.time()
    with _meta_cache_lock:
        ts, cached = _switch_info_map_cache
        if cached and (now - ts) < SITES_CACHE_TTL_SECONDS:
            return dict(cached)
    return None


def _fetch_site_clients_only(
    session: requests.Session,
    site: Dict[str, Any],
    site_ap_clients: int,
    rate_limit_flag: threading.Event,
) -> Tuple[str, List[Dict[str, Any]], Optional[str]]:
    site_id = site.get("id", "")
    site_name = site.get("name", site_id)
    if rate_limit_flag.is_set():
        return site_id, [], None

    clients: List[Dict[str, Any]] = []
    warning: Optional[str] = None
    try:
        # /api/v1/sites/{site_id}/stats/clients returns live connected clients and does NOT
        # support `page` pagination; sending page=1..N causes Mist to repeat the same list.
        clients = mist_get_paginated(
            session,
            f"/api/v1/sites/{site_id}/stats/clients",
            params={"wired": "false"},
            send_page_params=False,
            dedup_keys=("mac", "id"),
        )
        # Guard against Mist silently capping at default limit=100 without X-Page-* headers
        if len(clients) == 100 and site_ap_clients > 100:
            expanded = mist_get_paginated(
                session,
                f"/api/v1/sites/{site_id}/stats/clients",
                params={"wired": "false", "limit": max(10000, site_ap_clients * 2)},
                send_page_params=False,
                dedup_keys=("mac", "id"),
            )
            if len(expanded) > len(clients):
                clients = expanded
        # Exclude any wired client records defensively
        clients = [
            c
            for c in clients
            if isinstance(c, dict) and c.get("wired") is not True and c.get("is_wired") is not True
        ]
    except MistRateLimitError:
        rate_limit_flag.set()
        raise
    except Exception as exc:
        warning = f"Clients fetch failed for {site_name}: {exc}"

    return site_id, clients, warning


def _scan_slow_aps_from_sites(
    session: requests.Session,
    active_ap_sites: List[Dict[str, Any]],
    rate_limit_flag: threading.Event,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Fallback per-site AP uplink scan used only if org-wide AP stats omit port_stat (cached 30 min)."""
    slow_aps: List[Dict[str, Any]] = []
    warnings: List[str] = []

    def fetch_one(site: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if rate_limit_flag.is_set():
            return [], None
        site_id = site.get("id", "")
        site_name = site.get("name", site_id)
        try:
            aps = mist_get_paginated(
                session,
                f"/api/v1/sites/{site_id}/stats/devices",
                params={"type": "ap"},
                limit=1000,
                send_page_params=True,
                dedup_keys=("mac", "id"),
            )
        except MistRateLimitError:
            rate_limit_flag.set()
            raise
        except Exception as exc:
            return [], f"AP uplink check failed for {site_name}: {exc}"

        found: List[Dict[str, Any]] = []
        for ap in aps:
            if str(ap.get("status") or "").lower() != "connected":
                continue
            ip_stat = ap.get("ip_stat") if isinstance(ap.get("ip_stat"), dict) else {}
            ap_ip = str(ap.get("ip") or ip_stat.get("ip") or "").strip()
            for degraded in extract_ap_uplink_info(ap):
                found.append(
                    {
                        "name": ap.get("name") or ap.get("mac", "Unnamed AP"),
                        "site_name": site_name,
                        "model": ap.get("model", ""),
                        "mac": ap.get("mac", ""),
                        "ip": ap_ip,
                        "num_clients": int(ap.get("num_clients") or 0),
                        **degraded,
                    }
                )
        return found, None

    if not active_ap_sites:
        return slow_aps, warnings

    with ThreadPoolExecutor(max_workers=min(6, len(active_ap_sites))) as pool:
        futures = [pool.submit(fetch_one, site) for site in active_ap_sites]
        for fut in as_completed(futures):
            found, warn = fut.result()
            slow_aps.extend(found)
            if warn:
                warnings.append(warn)

    return slow_aps, warnings


def deduplicate_org_clients(
    site_map: Dict[str, Dict[str, Any]],
    site_clients: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Ensure each client MAC is counted at most once across the org (newest last_seen wins)."""
    best_by_mac: Dict[str, Tuple[float, str, Dict[str, Any]]] = {}
    unkeyed_by_site: Dict[str, List[Dict[str, Any]]] = {}

    for site_id in sorted(site_map.keys()):
        for client in site_clients.get(site_id, []):
            mac = str(client.get("mac") or "").strip().lower()
            if not mac:
                unkeyed_by_site.setdefault(site_id, []).append(client)
                continue
            last_seen = _item_last_seen(client)
            prev = best_by_mac.get(mac)
            if prev is None or last_seen > prev[0]:
                best_by_mac[mac] = (last_seen, site_id, client)

    deduped: Dict[str, List[Dict[str, Any]]] = {
        sid: list(unkeyed_by_site.get(sid, [])) for sid in site_map
    }
    for _, chosen_site_id, client_obj in best_by_mac.values():
        deduped[chosen_site_id].append(client_obj)
    return deduped


def _scan_vc_temps_from_sites(
    session: requests.Session,
    active_switch_sites: List[Dict[str, Any]],
    rate_limit_flag: threading.Event,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """Per-site switch/VC thermal & member/PFE health scan when org-wide switch stats omit module_stat."""
    items: List[Dict[str, Any]] = []
    member_issues: List[Dict[str, Any]] = []
    warnings: List[str] = []

    def fetch_one(site: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
        if rate_limit_flag.is_set():
            return [], [], None
        site_id = site.get("id", "")
        site_name = site.get("name", site_id)
        try:
            switches = mist_get_paginated(
                session,
                f"/api/v1/sites/{site_id}/stats/devices",
                params={"type": "switch"},
                limit=1000,
                send_page_params=True,
                dedup_keys=("mac", "id"),
            )
        except MistRateLimitError:
            rate_limit_flag.set()
            raise
        except Exception as exc:
            return [], [], f"Switch thermal scan failed for {site_name}: {exc}"

        found: List[Dict[str, Any]] = []
        found_issues: List[Dict[str, Any]] = []
        for sw in switches:
            info = extract_switch_thermal_info(sw, site_name)
            if info is not None:
                found.append(info)
            found_issues.extend(extract_vc_member_issues(sw, site_name))
        return found, found_issues, None

    if not active_switch_sites:
        return items, member_issues, warnings

    with ThreadPoolExecutor(max_workers=min(6, len(active_switch_sites))) as pool:
        futures = [pool.submit(fetch_one, site) for site in active_switch_sites]
        for fut in as_completed(futures):
            found, found_issues, warn = fut.result()
            items.extend(found)
            member_issues.extend(found_issues)
            if warn:
                warnings.append(warn)

    return items, member_issues, warnings


def collect_mist_snapshot() -> Dict[str, Any]:
    global _last_snapshot_call_count, _switch_info_map_cache, _slow_aps_cache, _active_ap_sites_cache, _vc_temps_cache, _vc_member_issues_cache, _active_switch_sites_cache
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise ValueError("MIST_ORG_ID and MIST_API_TOKEN must be configured in environment variables.")

    session = _new_mist_session()
    warnings: List[str] = []
    rate_limit_flag = threading.Event()

    try:
        org_info = _get_org_info_cached(session)
        sites_raw = _get_sites_raw_cached(session)

        site_map: Dict[str, Dict[str, Any]] = {
            s["id"]: s for s in sites_raw if isinstance(s, dict) and s.get("id")
        }

        # Fetch ALL org APs in 1-2 org-wide calls instead of 65+ per-site AP calls
        raw_org_aps = mist_get_paginated(
            session,
            f"/api/v1/orgs/{MIST_ORG_ID}/stats/devices",
            params={"type": "ap", "status": "all"},
            limit=1000,
            send_page_params=True,
            dedup_keys=("mac", "id"),
        )

        site_aps: Dict[str, List[Dict[str, Any]]] = {sid: [] for sid in site_map}
        org_aps_have_port_stat = False
        org_aps_report_clients = False
        for ap in raw_org_aps:
            if not isinstance(ap, dict):
                continue
            sid = str(ap.get("site_id") or "")
            if sid in site_aps:
                site_aps[sid].append(ap)
            if str(ap.get("status") or "").lower() == "connected":
                if isinstance(ap.get("port_stat"), dict) and ap.get("port_stat"):
                    org_aps_have_port_stat = True
                if ap.get("num_clients") is not None:
                    org_aps_report_clients = True

        # Only query /sites/{site_id}/stats/clients for sites with active connected clients
        active_client_sites: List[Tuple[Dict[str, Any], int]] = []
        active_ap_sites: List[Dict[str, Any]] = []
        for site_id, site in site_map.items():
            aps_for_site = site_aps.get(site_id, [])
            connected_aps = [
                ap for ap in aps_for_site if str(ap.get("status") or "").lower() == "connected"
            ]
            if connected_aps:
                active_ap_sites.append(site)
            ap_client_sum = sum(int(ap.get("num_clients") or 0) for ap in connected_aps)
            if (org_aps_report_clients and ap_client_sum > 0) or (
                not org_aps_report_clients and connected_aps
            ):
                active_client_sites.append((site, ap_client_sum))

        site_clients: Dict[str, List[Dict[str, Any]]] = {sid: [] for sid in site_map}
        if active_client_sites:
            with ThreadPoolExecutor(max_workers=min(6, len(active_client_sites))) as pool:
                futures = [
                    pool.submit(_fetch_site_clients_only, session, site, ap_clients_cnt, rate_limit_flag)
                    for site, ap_clients_cnt in active_client_sites
                ]
                for fut in as_completed(futures):
                    site_id, clients, warn = fut.result()
                    site_clients[site_id] = clients
                    if warn:
                        warnings.append(warn)

        site_clients = deduplicate_org_clients(site_map, site_clients)

        switches_online = 0
        switches_offline = 0
        offline_switches: List[Dict[str, Any]] = []
        switch_info_map: Dict[str, Dict[str, Any]] = {}
        active_switch_site_ids = set()
        org_switch_thermals: List[Dict[str, Any]] = []
        org_vc_member_issues: List[Dict[str, Any]] = []
        org_switches_had_module_stat = False
        try:
            raw_switches = mist_get_paginated(
                session,
                f"/api/v1/orgs/{MIST_ORG_ID}/stats/devices",
                params={"type": "switch", "status": "all"},
                limit=1000,
                send_page_params=True,
                dedup_keys=("mac", "id"),
            )
            for sw in raw_switches:
                sid = str(sw.get("site_id") or "")
                site_name = sw.get("site_name") or site_map.get(sid, {}).get("name", "Unassigned")
                ip_stat = sw.get("ip_stat") if isinstance(sw.get("ip_stat"), dict) else {}
                sw_ip = str(sw.get("ip") or ip_stat.get("ip") or "").strip()
                smac = normalize_mac(sw.get("mac"))
                if smac:
                    switch_info_map[smac] = {
                        "name": str(sw.get("name") or format_mac(smac)),
                        "site_id": sid,
                        "model": str(sw.get("model") or ""),
                        "ip": sw_ip,
                    }
                status = str(sw.get("status") or "").lower()
                if status == "connected":
                    switches_online += 1
                    if sid in site_map:
                        active_switch_site_ids.add(sid)
                    if isinstance(sw.get("module_stat"), list) and sw.get("module_stat"):
                        org_switches_had_module_stat = True
                    t_info = extract_switch_thermal_info(sw, site_name)
                    if t_info is not None:
                        org_switch_thermals.append(t_info)
                    org_vc_member_issues.extend(extract_vc_member_issues(sw, site_name))
                    continue
                switches_offline += 1
                offline_switches.append(
                    {
                        "device_type": "Switch",
                        "name": sw.get("name") or sw.get("mac", "Unnamed Switch"),
                        "site_name": site_name,
                        "model": sw.get("model", ""),
                        "mac": sw.get("mac", ""),
                        "ip": sw_ip,
                        "version": sw.get("version", ""),
                        "last_seen": sw.get("last_seen"),
                        "status": status or "disconnected",
                    }
                )
            active_switch_sites = [site_map[sid] for sid in active_switch_site_ids if sid in site_map]
            with _meta_cache_lock:
                if switch_info_map:
                    _switch_info_map_cache = (time.time(), switch_info_map)
                _active_switch_sites_cache = (time.time(), list(active_switch_sites))
                if org_switch_thermals:
                    _vc_temps_cache = (time.time(), list(org_switch_thermals), "org_stats")
                if org_switches_had_module_stat or org_vc_member_issues:
                    _vc_member_issues_cache = (time.time(), list(org_vc_member_issues), "org_stats")
        except MistRateLimitError:
            raise
        except Exception as exc:
            warnings.append(f"Switch stats unavailable: {exc}")

        alarms: List[Dict[str, Any]] = []
        alarm_vc_issues: List[Dict[str, Any]] = []
        try:
            alarms_resp = mist_get(
                session,
                f"/api/v1/orgs/{MIST_ORG_ID}/alarms/search",
                params={"duration": "1d", "limit": 50},
            )
            raw_alarms = alarms_resp.get("results", []) if isinstance(alarms_resp, dict) else []
            alarm_vc_issues = extract_vc_alarm_issues(raw_alarms, site_map, switch_info_map)
            for a in raw_alarms[:25]:
                sid = a.get("site_id", "")
                alarms.append(
                    {
                        "type": a.get("type", "alarm"),
                        "severity": a.get("severity", "info"),
                        "group": a.get("group", ""),
                        "site_name": a.get("site_name") or site_map.get(sid, {}).get("name", "Org"),
                        "text": a.get("text") or a.get("type", "").replace("_", " "),
                        "count": a.get("count", 1),
                        "timestamp": a.get("last_seen") or a.get("timestamp"),
                    }
                )
        except MistRateLimitError:
            raise
        except Exception as exc:
            warnings.append(f"Alarms unavailable: {exc}")

        total_wireless_users = 0
        total_ap_reported_clients = 0
        total_eduroam_users = 0
        total_uop_visitor_users = 0
        total_uop_connect_users = 0
        ssid_counts: Dict[str, int] = {}
        band_counts: Dict[str, int] = {"2.4 GHz": 0, "5 GHz": 0, "6 GHz": 0, "Other": 0}
        proto_counts: Dict[str, int] = {}
        rssi_values: List[float] = []

        aps_online = 0
        aps_offline = 0
        all_aps_list: List[Dict[str, Any]] = []
        offline_aps: List[Dict[str, Any]] = []
        slow_aps: List[Dict[str, Any]] = []
        sites_summary: List[Dict[str, Any]] = []

        for site_id, site in site_map.items():
            site_name = site.get("name", site_id)
            clients = site_clients.get(site_id, [])
            aps = site_aps.get(site_id, [])

            site_eduroam = 0
            site_uop_visitor = 0
            site_uop_connect = 0
            site_rssi: List[float] = []

            for c in clients:
                total_wireless_users += 1
                raw_ssid = (c.get("ssid") or "").strip()
                ssid_label = raw_ssid if raw_ssid else "(Unknown)"
                ssid_counts[ssid_label] = ssid_counts.get(ssid_label, 0) + 1

                ssid_norm = " ".join(raw_ssid.lower().replace("-", " ").replace("_", " ").split())
                if ssid_norm == "eduroam":
                    total_eduroam_users += 1
                    site_eduroam += 1
                elif ssid_norm in ("uop visitor", "uopvisitor"):
                    total_uop_visitor_users += 1
                    site_uop_visitor += 1
                elif ssid_norm in ("uop connect", "uopconnect"):
                    total_uop_connect_users += 1
                    site_uop_connect += 1

                band = normalize_band(c.get("band"))
                band_counts[band] = band_counts.get(band, 0) + 1

                proto = normalize_proto(c.get("proto"))
                proto_counts[proto] = proto_counts.get(proto, 0) + 1

                rssi = c.get("rssi")
                if isinstance(rssi, (int, float)):
                    rssi_values.append(float(rssi))
                    site_rssi.append(float(rssi))

            site_aps_on = 0
            site_aps_off = 0
            site_ap_clients = 0
            for ap in aps:
                status = str(ap.get("status") or "").lower()
                is_online = status == "connected"
                ap_name = ap.get("name") or ap.get("mac", "Unnamed AP")
                ap_model = ap.get("model", "")
                ap_mac = ap.get("mac", "")
                ip_stat = ap.get("ip_stat") if isinstance(ap.get("ip_stat"), dict) else {}
                ap_ip = str(ap.get("ip") or ip_stat.get("ip") or "").strip()
                ap_clients = int(ap.get("num_clients") or 0)

                if is_online:
                    aps_online += 1
                    site_aps_on += 1
                    site_ap_clients += ap_clients
                    total_ap_reported_clients += ap_clients
                    if org_aps_have_port_stat:
                        for degraded in extract_ap_uplink_info(ap):
                            slow_aps.append(
                                {
                                    "name": ap_name,
                                    "site_name": site_name,
                                    "model": ap_model,
                                    "mac": ap_mac,
                                    "ip": ap_ip,
                                    "num_clients": ap_clients,
                                    **degraded,
                                }
                            )
                else:
                    aps_offline += 1
                    site_aps_off += 1
                    offline_aps.append(
                        {
                            "device_type": "AP",
                            "name": ap_name,
                            "site_name": site_name,
                            "model": ap_model,
                            "mac": ap_mac,
                            "ip": ap_ip,
                            "version": ap.get("version", ""),
                            "last_seen": ap.get("last_seen"),
                            "status": status or "disconnected",
                        }
                    )

                all_aps_list.append(
                    {
                        "name": ap_name,
                        "site_name": site_name,
                        "model": ap_model,
                        "ip": ap_ip,
                        "num_clients": ap_clients,
                        "status": "connected" if is_online else (status or "disconnected"),
                    }
                )

            site_total = len(clients)
            site_other = max(0, site_total - site_eduroam - site_uop_visitor - site_uop_connect)
            sites_summary.append(
                {
                    "id": site_id,
                    "name": site_name,
                    "total_users": site_total,
                    "ap_reported_clients": site_ap_clients,
                    "eduroam_users": site_eduroam,
                    "uop_visitor_users": site_uop_visitor,
                    "uop_connect_users": site_uop_connect,
                    "other_users": site_other,
                    "aps_online": site_aps_on,
                    "aps_offline": site_aps_off,
                    "avg_rssi": round(sum(site_rssi) / len(site_rssi), 1) if site_rssi else None,
                }
            )

        # Cache active AP sites so on-demand POST /api/slow-aps/scan knows which sites to query
        with _meta_cache_lock:
            _active_ap_sites_cache = (time.time(), list(active_ap_sites))

        # Only populate slow_aps automatically if org-wide AP stats already included port_stat (0 extra calls).
        # Otherwise keep slow AP uplink scanning strictly on-demand via POST /api/slow-aps/scan.
        if org_aps_have_port_stat:
            with _meta_cache_lock:
                _slow_aps_cache = (time.time(), list(slow_aps), "org_stats")
        else:
            with _meta_cache_lock:
                _, items_slow, source_slow = _slow_aps_cache
                if items_slow is not None and source_slow != "not_scanned":
                    slow_aps = list(items_slow)

        slow_aps_meta = _build_slow_aps_meta(active_ap_sites_count=len(active_ap_sites))

        sites_summary.sort(key=lambda s: (-s["total_users"], s["name"].lower()))
        all_aps_list.sort(key=lambda a: (-a["num_clients"], a["name"].lower()))
        slow_aps.sort(key=lambda a: (a["speed"], a["site_name"].lower(), a["name"].lower()))
        offline_aps.sort(key=lambda d: (d["site_name"].lower(), d["name"].lower()))
        offline_switches.sort(key=lambda d: (d["site_name"].lower(), d["name"].lower()))
        devices_down = offline_switches + offline_aps

        ssids_sorted = sorted(
            [{"name": k, "count": v} for k, v in ssid_counts.items()],
            key=lambda x: (-x["count"], x["name"].lower()),
        )

        protos_sorted = sorted(
            [{"name": k, "count": v} for k, v in proto_counts.items()],
            key=lambda x: (-x["count"], x["name"]),
        )

        def pct(part: int) -> float:
            return round((part / total_wireless_users) * 100, 1) if total_wireless_users > 0 else 0.0

        other_wireless_users = max(
            0,
            total_wireless_users - total_eduroam_users - total_uop_visitor_users - total_uop_connect_users,
        )

        traffic_active_sites_count = sum(
            1
            for s in sites_summary
            if (int(s.get("aps_online") or 0) + int(s.get("aps_offline") or 0)) > 0
            or int(s.get("total_users") or 0) > 0
        )

        with _quota_lock:
            _last_snapshot_call_count = session.call_count

        merged_vc_member_issues = _merge_vc_member_issues(org_vc_member_issues, alarm_vc_issues)

        return {
            "org": {
                "id": MIST_ORG_ID,
                "name": org_info.get("name", "Mist Organization") if isinstance(org_info, dict) else "Mist Organization",
                "api_host": MIST_API_HOST,
            },
            "summary": {
                "total_wireless_users": total_wireless_users,
                "ap_reported_clients": total_ap_reported_clients,
                "eduroam_users": total_eduroam_users,
                "eduroam_pct": pct(total_eduroam_users),
                "uop_visitor_users": total_uop_visitor_users,
                "uop_visitor_pct": pct(total_uop_visitor_users),
                "uop_connect_users": total_uop_connect_users,
                "uop_connect_pct": pct(total_uop_connect_users),
                "other_wireless_users": other_wireless_users,
                "total_sites": len(sites_summary),
                "active_sites": sum(1 for s in sites_summary if s["total_users"] > 0),
                "aps_online": aps_online,
                "aps_offline": aps_offline,
                "aps_total": aps_online + aps_offline,
                "switches_online": switches_online,
                "switches_offline": switches_offline,
                "switches_total": switches_online + switches_offline,
                "devices_down_total": len(devices_down),
                "vc_member_issues_count": len(merged_vc_member_issues),
                "slow_aps_count": len(slow_aps) if slow_aps_meta["scanned"] else None,
                "slow_aps_scanned": slow_aps_meta["scanned"],
                "avg_rssi": round(sum(rssi_values) / len(rssi_values), 1) if rssi_values else None,
            },
            "sites": sites_summary,
            "ssids": ssids_sorted,
            "bands": band_counts,
            "protocols": protos_sorted,
            "top_aps": all_aps_list[:10],
            "offline_aps": offline_aps,
            "offline_switches": offline_switches,
            "devices_down": devices_down,
            "vc_member_issues": merged_vc_member_issues,
            "vc_alarm_issues": alarm_vc_issues,
            "slow_aps": slow_aps,
            "slow_aps_meta": slow_aps_meta,
            "vc_temps": [],
            "vc_temps_meta": _build_vc_temps_view(None)[1],
            "estimates": {
                "traffic_all_sites_calls": max(1, traffic_active_sites_count),
                "traffic_single_site_calls": 1,
                "slow_aps_scan_calls": slow_aps_meta["estimated_calls"],
                "vc_temps_scan_calls": _build_vc_temps_view(None)[1]["estimated_calls"],
                "nac_rejects_min_calls": 4,
                "nac_rejects_max_calls": 12,
            },
            "polling": get_polling_state(),
            "alarms": alarms,
            "warnings": warnings,
            "api_quota": get_mist_api_quota_snapshot(),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "cache_ttl_seconds": CACHE_TTL_SECONDS,
            "read_only": True,
        }
    finally:
        session.close()


def _client_ip() -> str:
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return fwd or (request.headers.get("X-Real-IP") or "").strip() or (request.remote_addr or "unknown")


def _check_login_rate_limit(client_ip: str) -> bool:
    """Return True if under rate limit, False if rate-limited."""
    now = time.time()
    cutoff = now - LOGIN_RATE_WINDOW_SECONDS
    with _auth_lock:
        recent = [ts for ts in _login_attempts.get(client_ip, []) if ts > cutoff]
        if len(recent) >= LOGIN_RATE_MAX_ATTEMPTS:
            _login_attempts[client_ip] = recent
            return False
        recent.append(now)
        _login_attempts[client_ip] = recent
        return True


def _attach_mist_csrf(mist_sess: requests.Session) -> None:
    """Attach Mist regional csrftoken* cookie as X-CSRFToken header."""
    for cookie in mist_sess.cookies:
        if cookie.name.startswith("csrftoken") and cookie.value:
            mist_sess.headers["X-CSRFToken"] = cookie.value
            return


def _logout_mist_session(mist_sess: requests.Session) -> None:
    """Best-effort cleanup of the ephemeral Mist auth session."""
    try:
        _attach_mist_csrf(mist_sess)
        mist_sess.post(f"{MIST_API_HOST}/api/v1/logout", timeout=5)
    except Exception:
        pass
    finally:
        try:
            mist_sess.close()
        except Exception:
            pass


def _prune_expired_challenges() -> None:
    now = time.time()
    expired_sessions: List[requests.Session] = []
    with _auth_lock:
        expired_ids = [
            cid
            for cid, entry in _pending_2fa.items()
            if now - entry.get("created_at", 0.0) > TWO_FACTOR_CHALLENGE_TTL_SECONDS
        ]
        for cid in expired_ids:
            entry = _pending_2fa.pop(cid, None)
            if entry and entry.get("session") is not None:
                expired_sessions.append(entry["session"])
    for sess in expired_sessions:
        _logout_mist_session(sess)


def _authorize_mist_user(
    mist_sess: requests.Session, self_data: Dict[str, Any]
) -> Tuple[bool, str]:
    """Verify the authenticated Mist user has privileges for MIST_ORG_ID."""
    if not MIST_ORG_ID:
        return False, ""

    privileges = self_data.get("privileges")
    if isinstance(privileges, list):
        org_roles: List[str] = []
        for priv in privileges:
            if not isinstance(priv, dict):
                continue
            if str(priv.get("org_id") or "").strip() == MIST_ORG_ID:
                role = str(priv.get("role") or "user").strip()
                scope = str(priv.get("scope") or "org").strip()
                org_roles.append(f"{role} ({scope})" if scope != "org" else role)
        if org_roles:
            return True, org_roles[0]

    # MSP-level admins may have access via msp_id without explicit org_id entry
    try:
        org_resp = mist_sess.get(f"{MIST_API_HOST}/api/v1/orgs/{MIST_ORG_ID}", timeout=15)
        if org_resp.status_code == 200:
            org_payload = org_resp.json()
            if isinstance(org_payload, dict) and str(org_payload.get("id") or "") == MIST_ORG_ID:
                msp_id = str(org_payload.get("msp_id") or "").strip()
                if msp_id and isinstance(privileges, list):
                    for priv in privileges:
                        if isinstance(priv, dict) and str(priv.get("msp_id") or "").strip() == msp_id:
                            return True, f"{priv.get('role', 'admin')} (msp)"
                return True, "org"
    except Exception:
        pass

    return False, ""


def _current_user() -> Optional[Dict[str, Any]]:
    email = flask_session.get("user_email")
    if not email:
        return None
    return {
        "email": email,
        "name": flask_session.get("user_name") or email,
        "role": flask_session.get("user_role") or "user",
    }


def _set_user_session(self_data: Dict[str, Any], role: str, fallback_email: str = "") -> Dict[str, Any]:
    email = str(self_data.get("email") or fallback_email or "").strip()
    first = str(self_data.get("first_name") or "").strip()
    last = str(self_data.get("last_name") or "").strip()
    full_name = " ".join(p for p in (first, last) if p) or email
    flask_session.clear()
    flask_session.permanent = True
    flask_session["user_email"] = email
    flask_session["user_name"] = full_name
    flask_session["user_role"] = role or "user"
    flask_session["auth_at"] = int(time.time())
    return {"email": email, "name": full_name, "role": role or "user"}


def _is_authenticated() -> bool:
    if not AUTH_REQUIRED:
        return True
    return _current_user() is not None


def _finalize_mist_login(
    mist_sess: requests.Session, fallback_email: str = ""
) -> Tuple[Any, int]:
    """Check /api/v1/self on an authenticated Mist session, handle 2FA or issue dashboard session."""
    _attach_mist_csrf(mist_sess)
    self_resp = mist_sess.get(f"{MIST_API_HOST}/api/v1/self", timeout=15)
    if self_resp.status_code != 200:
        _logout_mist_session(mist_sess)
        return jsonify({"error": "Failed to verify Mist account profile."}), 401

    self_data = self_resp.json()
    if not isinstance(self_data, dict):
        _logout_mist_session(mist_sess)
        return jsonify({"error": "Unexpected response from Mist /self endpoint."}), 502

    if self_data.get("two_factor_required") is True and self_data.get("two_factor_passed") is False:
        challenge_id = secrets.token_urlsafe(32)
        with _auth_lock:
            _pending_2fa[challenge_id] = {
                "session": mist_sess,
                "email": str(self_data.get("email") or fallback_email or "").strip(),
                "created_at": time.time(),
                "attempts": 0,
            }
        return jsonify(
            {
                "status": "two_factor_required",
                "challenge_id": challenge_id,
                "email": str(self_data.get("email") or fallback_email or "").strip(),
            }
        ), 200

    authorized, role = _authorize_mist_user(mist_sess, self_data)
    _logout_mist_session(mist_sess)

    if not authorized:
        return jsonify(
            {"error": "Access denied: your Mist account is not authorised for this organisation."}
        ), 403

    user = _set_user_session(self_data, role, fallback_email=fallback_email)
    return jsonify({"status": "authenticated", "user": user}), 200


@app.get("/login")
def login_page():
    if _is_authenticated():
        return redirect("/")
    return send_from_directory(str(BASE_DIR), "login.html")


@app.get("/api/auth/me")
def api_auth_me():
    user = _current_user()
    resp = jsonify(
        {
            "auth_required": AUTH_REQUIRED,
            "authenticated": _is_authenticated(),
            "user": user,
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/auth/login")
def api_auth_login():
    _prune_expired_challenges()
    if not _check_login_rate_limit(_client_ip()):
        return jsonify({"error": "Too many sign-in attempts. Please wait a few minutes and try again."}), 429

    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("password") or "")
    two_factor = str(payload.get("two_factor") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    if not MIST_ORG_ID:
        return jsonify({"error": "Server MIST_ORG_ID is not configured."}), 500

    mist_sess = requests.Session()
    mist_sess.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    login_body: Dict[str, Any] = {"email": email, "password": password}
    if two_factor:
        login_body["two_factor"] = two_factor

    try:
        resp = mist_sess.post(f"{MIST_API_HOST}/api/v1/login", json=login_body, timeout=15)
    except Exception:
        mist_sess.close()
        return jsonify({"error": "Could not reach Juniper Mist EU authentication service."}), 502

    if resp.status_code != 200:
        detail = "Invalid Mist email or password."
        try:
            err_json = resp.json()
            if isinstance(err_json, dict) and err_json.get("detail"):
                detail = str(err_json["detail"])
        except Exception:
            pass
        mist_sess.close()
        return jsonify({"error": detail}), 401

    login_data = {}
    try:
        login_data = resp.json() if resp.content else {}
    except Exception:
        login_data = {}

    _attach_mist_csrf(mist_sess)

    # Check if Mist already indicated 2FA is required on the login response
    if (
        isinstance(login_data, dict)
        and login_data.get("two_factor_required") is True
        and login_data.get("two_factor_passed") is False
    ):
        challenge_id = secrets.token_urlsafe(32)
        with _auth_lock:
            _pending_2fa[challenge_id] = {
                "session": mist_sess,
                "email": str(login_data.get("email") or email).strip(),
                "created_at": time.time(),
                "attempts": 0,
            }
        return jsonify(
            {
                "status": "two_factor_required",
                "challenge_id": challenge_id,
                "email": str(login_data.get("email") or email).strip(),
            }
        ), 200

    try:
        return _finalize_mist_login(mist_sess, fallback_email=email)
    except Exception:
        _logout_mist_session(mist_sess)
        return jsonify({"error": "Could not verify Mist organisation membership."}), 502


@app.post("/api/auth/two-factor")
def api_auth_two_factor():
    _prune_expired_challenges()
    if not _check_login_rate_limit(_client_ip()):
        return jsonify({"error": "Too many verification attempts. Please wait a few minutes and try again."}), 429

    payload = request.get_json(silent=True) or {}
    challenge_id = str(payload.get("challenge_id") or "").strip()
    two_factor = str(payload.get("two_factor") or "").strip().replace(" ", "")

    if not challenge_id or not two_factor:
        return jsonify({"error": "Verification code is required."}), 400

    expired_session: Optional[requests.Session] = None
    with _auth_lock:
        entry = _pending_2fa.get(challenge_id)
        if not entry:
            return jsonify({"error": "Your 2FA session has expired. Please sign in again."}), 410
        if entry["attempts"] >= TWO_FACTOR_MAX_ATTEMPTS:
            expired_entry = _pending_2fa.pop(challenge_id, None)
            if expired_entry:
                expired_session = expired_entry.get("session")
        else:
            entry["attempts"] += 1
            mist_sess = entry["session"]
            email = entry.get("email", "")

    if expired_session is not None:
        _logout_mist_session(expired_session)
        return jsonify({"error": "Too many invalid 2FA codes. Please sign in again."}), 410

    _attach_mist_csrf(mist_sess)
    try:
        tf_resp = mist_sess.post(
            f"{MIST_API_HOST}/api/v1/login/two_factor",
            json={"two_factor": two_factor},
            timeout=15,
        )
    except Exception:
        return jsonify({"error": "Could not reach Juniper Mist EU 2FA service."}), 502

    if tf_resp.status_code != 200:
        detail = "Invalid 2FA verification code. Please try again."
        try:
            err_json = tf_resp.json()
            if isinstance(err_json, dict) and err_json.get("detail"):
                detail = str(err_json["detail"])
        except Exception:
            pass
        return jsonify({"error": detail}), 401

    with _auth_lock:
        _pending_2fa.pop(challenge_id, None)

    try:
        return _finalize_mist_login(mist_sess, fallback_email=email)
    except Exception:
        _logout_mist_session(mist_sess)
        return jsonify({"error": "Could not verify Mist organisation membership."}), 502


@app.post("/api/auth/logout")
def api_auth_logout():
    flask_session.clear()
    return jsonify({"ok": True})


@app.get("/")
def index():
    if not _is_authenticated():
        return redirect("/login")
    resp = send_from_directory(str(BASE_DIR), "index.html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/favicon.svg")
def favicon_svg():
    resp = send_from_directory(str(BASE_DIR), "favicon.svg", mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.get("/favicon.ico")
def favicon_ico():
    resp = send_from_directory(str(BASE_DIR), "favicon.ico", mimetype="image/x-icon")
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "read_only": True,
            "auth_required": AUTH_REQUIRED,
            "https_enabled": HTTPS_ENABLED,
            "api_host": MIST_API_HOST,
            "configured": bool(MIST_ORG_ID and MIST_API_TOKEN),
            "cache_ttl_seconds": CACHE_TTL_SECONDS,
            "polling": get_polling_state(),
            "api_quota": get_mist_api_quota_snapshot(),
        }
    )


def _get_merged_vc_member_issues(
    alarm_issues: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Merge cached telemetry VC member/PFE issues with active Mist alarm-based VC issues."""
    with _meta_cache_lock:
        ts_mem, items_mem, source_mem = _vc_member_issues_cache
    if alarm_issues is None:
        with _cache_lock:
            alarm_issues = list((_cache_data or {}).get("vc_alarm_issues") or [])
    merged = _merge_vc_member_issues(items_mem, alarm_issues)
    meta = {
        "scanned": source_mem != "not_scanned",
        "source": source_mem,
        "scanned_at": datetime.fromtimestamp(ts_mem, tz=timezone.utc).isoformat() if ts_mem > 0 else None,
        "count": len(merged),
        "telemetry_count": len(items_mem),
        "alarm_count": len(alarm_issues),
    }
    return merged, meta


def _attach_live_stats_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure cached/fresh /api/stats payloads reflect latest polling state, quota, slow AP scan, VC thermal, and VC member/PFE caches."""
    with _meta_cache_lock:
        _, items_slow, source_slow = _slow_aps_cache
    slow_meta = _build_slow_aps_meta()
    payload["slow_aps_meta"] = slow_meta
    summary = dict(payload.get("summary") or {})
    if items_slow is not None and source_slow != "not_scanned":
        payload["slow_aps"] = list(items_slow)
        summary["slow_aps_count"] = len(items_slow)
        summary["slow_aps_scanned"] = True

    vc_evaluated, vc_meta = _build_vc_temps_view(None)
    payload["vc_temps"] = vc_evaluated
    payload["vc_temps_meta"] = vc_meta
    summary["vc_temps_scanned"] = vc_meta["scanned"]
    summary["vc_temp_alarms_count"] = vc_meta["alarmed_count"] if vc_meta["scanned"] else None
    summary["vc_max_temp_c"] = vc_meta["max_temp_c"]

    vc_member_issues, vc_member_meta = _get_merged_vc_member_issues(payload.get("vc_alarm_issues") or [])
    payload["vc_member_issues"] = vc_member_issues
    payload["vc_member_issues_meta"] = vc_member_meta
    summary["vc_member_issues_count"] = len(vc_member_issues)

    payload["summary"] = summary

    estimates = dict(payload.get("estimates") or {})
    estimates["slow_aps_scan_calls"] = slow_meta["estimated_calls"]
    estimates["vc_temps_scan_calls"] = vc_meta["estimated_calls"]
    payload["estimates"] = estimates
    payload["polling"] = get_polling_state()
    payload["api_quota"] = get_mist_api_quota_snapshot()
    payload["auth_user"] = _current_user()
    return payload


def _serve_cached_stats_if_valid(force_refresh: bool) -> Optional[Dict[str, Any]]:
    now = time.time()
    paused = _is_polling_paused()
    with _cache_lock:
        cache_age = now - _cache_timestamp
        can_use_cache = _cache_data is not None and (
            (not force_refresh and (paused or cache_age < CACHE_TTL_SECONDS))
            or (force_refresh and cache_age < MIN_REFRESH_INTERVAL)
        )
        if can_use_cache and _cache_data is not None:
            payload = dict(_cache_data)
            payload["cached"] = True
            payload["cache_age_seconds"] = int(cache_age)
            return _attach_live_stats_fields(payload)
    return None


@app.get("/api/stats")
def api_stats():
    global _cache_data, _cache_timestamp
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401

    force_refresh = request.args.get("refresh") == "1"
    cached_payload = _serve_cached_stats_if_valid(force_refresh)
    if cached_payload is not None:
        resp = jsonify(cached_payload)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # Single-flight lock: concurrent tabs or background collector share one Mist fetch
    with _snapshot_fetch_lock:
        cached_payload = _serve_cached_stats_if_valid(force_refresh)
        if cached_payload is not None:
            resp = jsonify(cached_payload)
            resp.headers["Cache-Control"] = "no-store"
            return resp

        try:
            fresh_data = collect_mist_snapshot()
        except MistRateLimitError as exc:
            return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 500
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
        except Exception as exc:
            return jsonify({"error": f"Failed to query Mist EU API: {exc}"}), 502

        with _cache_lock:
            _cache_data = fresh_data
            _cache_timestamp = time.time()

        try:
            record_snapshot(HISTORY_DB_PATH, fresh_data)
        except Exception:
            pass

    payload = dict(fresh_data)
    payload["cached"] = False
    payload["cache_age_seconds"] = 0
    _attach_live_stats_fields(payload)
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/polling/state")
def api_polling_state_get():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    resp = jsonify({**get_polling_state(), "api_quota": get_mist_api_quota_snapshot()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/polling/state")
def api_polling_state_post():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401

    payload = request.get_json(silent=True) or {}
    current_paused = _is_polling_paused()
    next_paused: Optional[bool] = None

    if "paused" in payload:
        raw = payload.get("paused")
        if isinstance(raw, bool):
            next_paused = raw
        elif isinstance(raw, str):
            next_paused = raw.strip().lower() in ("1", "true", "yes", "paused")
        else:
            next_paused = bool(raw)
    elif "enabled" in payload:
        raw = payload.get("enabled")
        enabled_val = raw if isinstance(raw, bool) else str(raw).strip().lower() in ("1", "true", "yes", "active")
        next_paused = not enabled_val
    elif "action" in payload:
        action = str(payload.get("action") or "").strip().lower()
        if action == "pause":
            next_paused = True
        elif action in ("resume", "active", "start"):
            next_paused = False
        elif action == "toggle":
            next_paused = not current_paused
    else:
        next_paused = not current_paused

    if next_paused is None:
        return jsonify({"error": "Provide 'paused' (boolean) or 'action' ('pause'|'resume'|'toggle')."}), 400

    user = _current_user()
    actor = (user.get("email") or user.get("name")) if isinstance(user, dict) else "operator"
    state = set_polling_paused(next_paused, actor=actor)
    resp = jsonify({**state, "api_quota": get_mist_api_quota_snapshot()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/slow-aps/scan")
def api_slow_aps_scan():
    global _slow_aps_cache, _active_ap_sites_cache, _cache_data
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    payload = request.get_json(silent=True) or {}
    force_scan = bool(payload.get("force", True))

    with _slow_aps_scan_lock:
        now = time.time()
        with _meta_cache_lock:
            ts_slow, items_slow, source_slow = _slow_aps_cache
            _, cached_active_sites = _active_ap_sites_cache
        age = now - ts_slow if ts_slow > 0 else 1e9
        if items_slow is not None and source_slow != "not_scanned" and (
            (not force_scan and age < SLOW_AP_CACHE_TTL_SECONDS)
            or (force_scan and age < MIN_REFRESH_INTERVAL)
        ):
            meta = _build_slow_aps_meta(calls_used=0)
            resp = jsonify(
                {
                    "slow_aps": list(items_slow),
                    "slow_aps_count": len(items_slow),
                    "slow_aps_meta": meta,
                    "cached": True,
                    "calls_used": 0,
                    "warnings": [],
                    "api_quota": get_mist_api_quota_snapshot(),
                }
            )
            resp.headers["Cache-Control"] = "no-store"
            return resp

        session = _new_mist_session()
        rate_limit_flag = threading.Event()
        warnings: List[str] = []
        slow_aps: List[Dict[str, Any]] = []
        source_label = "on_demand"

        try:
            active_ap_sites = list(cached_active_sites)
            if not active_ap_sites:
                # Derive active AP sites from cached snapshot or Mist sites/devices
                with _cache_lock:
                    if isinstance(_cache_data, dict):
                        active_ap_sites = [
                            {"id": s["id"], "name": s.get("name") or s["id"]}
                            for s in (_cache_data.get("sites") or [])
                            if isinstance(s, dict) and s.get("id") and int(s.get("aps_online") or 0) > 0
                        ]

            if not active_ap_sites:
                sites_raw = _get_sites_raw_cached(session)
                site_map = {s["id"]: s for s in sites_raw if isinstance(s, dict) and s.get("id")}
                raw_org_aps = mist_get_paginated(
                    session,
                    f"/api/v1/orgs/{MIST_ORG_ID}/stats/devices",
                    params={"type": "ap", "status": "connected"},
                    limit=1000,
                    send_page_params=True,
                    dedup_keys=("mac", "id"),
                )
                org_has_port_stat = any(
                    isinstance(ap, dict) and isinstance(ap.get("port_stat"), dict) and ap.get("port_stat")
                    for ap in raw_org_aps
                )
                active_ids = set()
                for ap in raw_org_aps:
                    if not isinstance(ap, dict):
                        continue
                    sid = str(ap.get("site_id") or "")
                    if sid in site_map:
                        active_ids.add(sid)
                    if org_has_port_stat:
                        site_name = site_map.get(sid, {}).get("name", sid or "Unknown Site")
                        ip_stat = ap.get("ip_stat") if isinstance(ap.get("ip_stat"), dict) else {}
                        ap_ip = str(ap.get("ip") or ip_stat.get("ip") or "").strip()
                        for degraded in extract_ap_uplink_info(ap):
                            slow_aps.append(
                                {
                                    "name": ap.get("name") or ap.get("mac", "Unnamed AP"),
                                    "site_name": site_name,
                                    "model": ap.get("model", ""),
                                    "mac": ap.get("mac", ""),
                                    "ip": ap_ip,
                                    "num_clients": int(ap.get("num_clients") or 0),
                                    **degraded,
                                }
                            )
                active_ap_sites = [site_map[sid] for sid in active_ids if sid in site_map]
                with _meta_cache_lock:
                    _active_ap_sites_cache = (time.time(), list(active_ap_sites))
                if org_has_port_stat:
                    source_label = "org_stats"
                elif active_ap_sites:
                    slow_aps, warnings = _scan_slow_aps_from_sites(session, active_ap_sites, rate_limit_flag)
            else:
                slow_aps, warnings = _scan_slow_aps_from_sites(session, active_ap_sites, rate_limit_flag)
        except MistRateLimitError as exc:
            return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
        except Exception as exc:
            return jsonify({"error": f"Failed to scan AP uplinks: {exc}"}), 502
        finally:
            calls_used = session.call_count
            session.close()

        slow_aps.sort(key=lambda a: (a["speed"], a["site_name"].lower(), a["name"].lower()))

        with _meta_cache_lock:
            _slow_aps_cache = (time.time(), list(slow_aps), source_label)
            active_cnt = len(_active_ap_sites_cache[1]) or len(active_ap_sites)

        meta = _build_slow_aps_meta(active_ap_sites_count=active_cnt, calls_used=calls_used)

        with _cache_lock:
            if isinstance(_cache_data, dict):
                _cache_data["slow_aps"] = list(slow_aps)
                _cache_data["slow_aps_meta"] = meta
                summary = _cache_data.get("summary")
                if isinstance(summary, dict):
                    summary["slow_aps_count"] = len(slow_aps)
                    summary["slow_aps_scanned"] = True

    resp = jsonify(
        {
            "slow_aps": slow_aps,
            "slow_aps_count": len(slow_aps),
            "slow_aps_meta": meta,
            "cached": False,
            "calls_used": calls_used,
            "warnings": warnings,
            "api_quota": get_mist_api_quota_snapshot(),
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/vc-temps/scan")
def api_vc_temps_scan():
    global _vc_temps_cache, _vc_member_issues_cache, _active_switch_sites_cache
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    payload = request.get_json(silent=True) or {}
    force_scan = bool(payload.get("force", True))

    with _vc_temps_scan_lock:
        now = time.time()
        with _meta_cache_lock:
            ts_vc, items_vc, source_vc = _vc_temps_cache
            _, cached_sw_sites = _active_switch_sites_cache
        age = now - ts_vc if ts_vc > 0 else 1e9
        if items_vc is not None and source_vc != "not_scanned" and (
            (not force_scan and age < VC_TEMP_CACHE_TTL_SECONDS)
            or (force_scan and age < MIN_REFRESH_INTERVAL)
        ):
            evaluated, meta = _build_vc_temps_view(items_vc, calls_used=0)
            vc_member_issues, vc_member_meta = _get_merged_vc_member_issues()
            resp = jsonify(
                {
                    "vc_temps": evaluated,
                    "vc_temps_meta": meta,
                    "vc_member_issues": vc_member_issues,
                    "vc_member_issues_meta": vc_member_meta,
                    "cached": True,
                    "calls_used": 0,
                    "warnings": [],
                    "api_quota": get_mist_api_quota_snapshot(),
                }
            )
            resp.headers["Cache-Control"] = "no-store"
            return resp

        session = _new_mist_session()
        rate_limit_flag = threading.Event()
        warnings: List[str] = []
        thermals: List[Dict[str, Any]] = []
        member_issues: List[Dict[str, Any]] = []
        source_label = "on_demand"

        try:
            active_sw_sites = list(cached_sw_sites)
            if not active_sw_sites or source_vc == "org_stats":
                sites_raw = _get_sites_raw_cached(session)
                site_map = {s["id"]: s for s in sites_raw if isinstance(s, dict) and s.get("id")}
                raw_switches = mist_get_paginated(
                    session,
                    f"/api/v1/orgs/{MIST_ORG_ID}/stats/devices",
                    params={"type": "switch", "status": "connected"},
                    limit=1000,
                    send_page_params=True,
                    dedup_keys=("mac", "id"),
                )
                active_ids = set()
                had_org_module_stat = False
                for sw in raw_switches:
                    if not isinstance(sw, dict):
                        continue
                    sid = str(sw.get("site_id") or "")
                    if sid in site_map:
                        active_ids.add(sid)
                    sname = sw.get("site_name") or site_map.get(sid, {}).get("name", "Unassigned")
                    if isinstance(sw.get("module_stat"), list) and sw.get("module_stat"):
                        had_org_module_stat = True
                    info = extract_switch_thermal_info(sw, sname)
                    if info is not None:
                        thermals.append(info)
                    member_issues.extend(extract_vc_member_issues(sw, sname))
                active_sw_sites = [site_map[sid] for sid in active_ids if sid in site_map]
                with _meta_cache_lock:
                    _active_switch_sites_cache = (time.time(), list(active_sw_sites))
                if thermals or had_org_module_stat:
                    source_label = "org_stats"
                elif active_sw_sites:
                    thermals, member_issues, warnings = _scan_vc_temps_from_sites(
                        session, active_sw_sites, rate_limit_flag
                    )
            else:
                thermals, member_issues, warnings = _scan_vc_temps_from_sites(
                    session, active_sw_sites, rate_limit_flag
                )
        except MistRateLimitError as exc:
            return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
        except Exception as exc:
            return jsonify({"error": f"Failed to scan Virtual Chassis telemetry: {exc}"}), 502
        finally:
            calls_used = session.call_count
            session.close()

        scan_ts = time.time()
        with _meta_cache_lock:
            _vc_temps_cache = (scan_ts, list(thermals), source_label)
            _vc_member_issues_cache = (scan_ts, list(member_issues), source_label)
            active_cnt = len(_active_switch_sites_cache[1]) or len(active_sw_sites)

        evaluated, meta = _build_vc_temps_view(
            thermals,
            active_switch_sites_count=active_cnt,
            calls_used=calls_used,
        )
        vc_member_issues, vc_member_meta = _get_merged_vc_member_issues()

    resp = jsonify(
        {
            "vc_temps": evaluated,
            "vc_temps_meta": meta,
            "vc_member_issues": vc_member_issues,
            "vc_member_issues_meta": vc_member_meta,
            "cached": False,
            "calls_used": calls_used,
            "warnings": warnings,
            "api_quota": get_mist_api_quota_snapshot(),
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/vc-temps/threshold")
def api_vc_temps_threshold():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401

    payload = request.get_json(silent=True) or {}
    raw_val = payload.get("threshold_c")
    try:
        val = float(raw_val)
    except (TypeError, ValueError):
        return jsonify({"error": "Provide a valid numeric 'threshold_c' between 25 and 95 °C."}), 400
    if not (25.0 <= val <= 95.0):
        return jsonify({"error": "Temperature threshold must be between 25°C and 95°C."}), 400

    updated = set_vc_temp_threshold_c(val)
    evaluated, meta = _build_vc_temps_view(None)
    resp = jsonify(
        {
            "threshold_c": updated,
            "vc_temps": evaluated,
            "vc_temps_meta": meta,
        }
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/history")
def api_history():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401

    range_type = (request.args.get("range") or "day").strip().lower()
    anchor = (request.args.get("anchor") or "").strip() or None
    ssid = (request.args.get("ssid") or "all").strip() or "all"

    try:
        data = query_history(
            HISTORY_DB_PATH,
            range_type=range_type,
            anchor=anchor,
            ssid=ssid,
        )
    except Exception as exc:
        return jsonify({"error": f"Failed to load Wi-Fi history: {exc}"}), 500

    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


_nac_cache_lock = threading.Lock()
_nac_fetch_lock = threading.Lock()
_nac_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _serve_cached_nac_if_valid(duration: str, force_refresh: bool) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _nac_cache_lock:
        cached_entry = _nac_cache.get(duration)
        if cached_entry is not None:
            cached_ts, cached_payload = cached_entry
            age = now - cached_ts
            if (not force_refresh and age < NAC_CACHE_TTL_SECONDS) or (
                force_refresh and age < MIN_REFRESH_INTERVAL
            ):
                out = dict(cached_payload)
                out["cached"] = True
                out["calls_used"] = 0
                out["cache_age_seconds"] = int(age)
                out["cache_ttl_seconds"] = NAC_CACHE_TTL_SECONDS
                out["api_quota"] = get_mist_api_quota_snapshot()
                return out
    return None


@app.get("/api/nac-rejects")
def api_nac_rejects():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    duration = "24h"
    force_refresh = request.args.get("refresh") == "1"

    cached_out = _serve_cached_nac_if_valid(duration, force_refresh)
    if cached_out is not None:
        resp = jsonify(cached_out)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    with _nac_fetch_lock:
        cached_out = _serve_cached_nac_if_valid(duration, force_refresh)
        if cached_out is not None:
            resp = jsonify(cached_out)
            resp.headers["Cache-Control"] = "no-store"
            return resp

        site_name_map = _cached_site_name_map()
        switch_info_map = _cached_switch_info_map()

        session = _new_mist_session()
        try:
            templates = _get_network_templates_cached(session)
            fresh = collect_nac_server_rejects(
                session=session,
                api_host=MIST_API_HOST,
                org_id=MIST_ORG_ID,
                duration=duration,
                site_name_map=site_name_map,
                switch_info_map=switch_info_map,
                network_templates=templates,
            )
        except MistRateLimitError as exc:
            return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
        except Exception as exc:
            return jsonify({"error": f"Failed to query Mist NAC server rejects: {exc}"}), 502
        finally:
            calls_used = session.call_count
            session.close()

        fresh["fetched_at"] = datetime.now(timezone.utc).isoformat()
        fresh["cache_ttl_seconds"] = NAC_CACHE_TTL_SECONDS
        with _nac_cache_lock:
            _nac_cache[duration] = (time.time(), fresh)

    out = dict(fresh)
    out["cached"] = False
    out["calls_used"] = calls_used
    out["cache_age_seconds"] = 0
    out["api_quota"] = get_mist_api_quota_snapshot()
    resp = jsonify(out)
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _cached_site_name_map() -> Optional[Dict[str, str]]:
    site_name_map: Dict[str, str] = {}
    with _cache_lock:
        if isinstance(_cache_data, dict):
            for s in _cache_data.get("sites") or []:
                if isinstance(s, dict) and s.get("id"):
                    site_name_map[str(s["id"])] = str(s.get("name") or s["id"])
    return site_name_map or None


@app.get("/api/client-lookup/search")
def api_client_lookup_search():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    query = (request.args.get("q") or "").strip()
    mode = (request.args.get("mode") or "auto").strip().lower()
    duration = (request.args.get("duration") or "7d").strip().lower()

    session = _new_mist_session()
    try:
        data = search_wifi_clients(
            session=session,
            api_host=MIST_API_HOST,
            org_id=MIST_ORG_ID,
            query=query,
            mode=mode,
            duration=duration,
            site_name_map=_cached_site_name_map(),
        )
    except MistRateLimitError as exc:
        return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Client lookup failed: {exc}"}), 502
    finally:
        session.close()

    data["fetched_at"] = datetime.now(timezone.utc).isoformat()
    data["api_quota"] = get_mist_api_quota_snapshot()
    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/client-lookup/detail")
def api_client_lookup_detail():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    mac = (request.args.get("mac") or "").strip()
    site_id = (request.args.get("site_id") or "").strip() or None
    duration = (request.args.get("duration") or "7d").strip().lower()

    session = _new_mist_session()
    try:
        data = get_wifi_client_detail(
            session=session,
            api_host=MIST_API_HOST,
            org_id=MIST_ORG_ID,
            mac=mac,
            site_id=site_id,
            duration=duration,
            site_name_map=_cached_site_name_map(),
        )
    except MistRateLimitError as exc:
        return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Failed to load client details: {exc}"}), 502
    finally:
        session.close()

    data["fetched_at"] = datetime.now(timezone.utc).isoformat()
    data["api_quota"] = get_mist_api_quota_snapshot()
    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


_traffic_cache_lock = threading.Lock()
_traffic_fetch_lock = threading.Lock()
_traffic_cache: Dict[Tuple[Any, ...], Tuple[float, Dict[str, Any]]] = {}
TRAFFIC_CACHE_TTL_SECONDS = int(os.getenv("TRAFFIC_CACHE_TTL_SECONDS", "900"))
TRAFFIC_CACHE_MAX_ENTRIES = 64


def _cached_prioritized_site_ids() -> List[str]:
    ordered: List[str] = []
    with _cache_lock:
        if isinstance(_cache_data, dict):
            for s in _cache_data.get("sites") or []:
                if not isinstance(s, dict) or not s.get("id"):
                    continue
                aps_count = int(s.get("aps_online") or 0) + int(s.get("aps_offline") or 0)
                users_count = int(s.get("total_users") or 0)
                if aps_count > 0 or users_count > 0:
                    ordered.append(str(s["id"]))
    return ordered


def _serve_cached_traffic_if_valid(
    cache_key: Tuple[Any, ...], force_refresh: bool
) -> Optional[Dict[str, Any]]:
    now = time.time()
    with _traffic_cache_lock:
        cached_entry = _traffic_cache.get(cache_key)
        if cached_entry is not None:
            cached_ts, cached_payload = cached_entry
            age = now - cached_ts
            if (not force_refresh and age < TRAFFIC_CACHE_TTL_SECONDS) or (
                force_refresh and age < MIN_REFRESH_INTERVAL
            ):
                out = dict(cached_payload)
                out["cached"] = True
                out["calls_used"] = 0
                out["cache_age_seconds"] = int(age)
                out["api_quota"] = get_mist_api_quota_snapshot()
                return out
    return None


@app.get("/api/traffic")
def api_traffic():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    days_raw = (request.args.get("days") or "5").strip()
    try:
        days = int(days_raw)
    except ValueError:
        days = 5
    if days not in (1, 5, 7):
        days = 5

    try:
        start_ts = parse_local_datetime_to_epoch(request.args.get("start"))
        end_ts = parse_local_datetime_to_epoch(request.args.get("end"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    site_id = (request.args.get("site_id") or "all").strip() or "all"
    force_refresh = request.args.get("refresh") == "1"
    cache_key = (days, site_id, start_ts, end_ts)

    cached_out = _serve_cached_traffic_if_valid(cache_key, force_refresh)
    if cached_out is not None:
        resp = jsonify(cached_out)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    with _traffic_fetch_lock:
        cached_out = _serve_cached_traffic_if_valid(cache_key, force_refresh)
        if cached_out is not None:
            resp = jsonify(cached_out)
            resp.headers["Cache-Control"] = "no-store"
            return resp

        session = _new_mist_session()
        try:
            fresh = collect_traffic_usage(
                session=session,
                api_host=MIST_API_HOST,
                org_id=MIST_ORG_ID,
                days=days,
                site_id=site_id,
                site_name_map=_cached_site_name_map(),
                prioritized_site_ids=_cached_prioritized_site_ids(),
                start_ts=start_ts,
                end_ts=end_ts,
            )
        except MistRateLimitError as exc:
            return jsonify({"error": str(exc), "api_quota": get_mist_api_quota_snapshot()}), 429
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 502
            return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
        except Exception as exc:
            return jsonify({"error": f"Failed to query Mist traffic usage: {exc}"}), 502
        finally:
            calls_used = session.call_count
            session.close()

        fresh["fetched_at"] = datetime.now(timezone.utc).isoformat()
        # Only cache valid non-partial responses so transient rate limits or empty errors never stick in cache
        has_data = (fresh.get("summary") or {}).get("total_bytes", 0) > 0
        if has_data and not fresh.get("warnings"):
            with _traffic_cache_lock:
                if len(_traffic_cache) >= TRAFFIC_CACHE_MAX_ENTRIES:
                    oldest_key = min(_traffic_cache.items(), key=lambda kv: kv[1][0])[0]
                    _traffic_cache.pop(oldest_key, None)
                _traffic_cache[cache_key] = (time.time(), fresh)

    out = dict(fresh)
    out["cached"] = False
    out["calls_used"] = calls_used
    out["cache_age_seconds"] = 0
    out["api_quota"] = get_mist_api_quota_snapshot()
    resp = jsonify(out)
    resp.headers["Cache-Control"] = "no-store"
    return resp


_collector_started = False
_collector_lock = threading.Lock()


def _history_collector_loop() -> None:
    """Continuously record Mist Wi-Fi client snapshots in the background when auto-sync is active."""
    global _cache_data, _cache_timestamp
    _polling_wake_event.wait(timeout=8)
    _polling_wake_event.clear()
    while True:
        try:
            if not _is_polling_paused():
                with _snapshot_fetch_lock:
                    if not _is_polling_paused():
                        with _cache_lock:
                            cache_age = time.time() - _cache_timestamp
                            has_recent_cache = _cache_data is not None and cache_age < max(
                                60, HISTORY_SAMPLE_INTERVAL_SECONDS - 15
                            )
                        if not has_recent_cache:
                            fresh_data = collect_mist_snapshot()
                            with _cache_lock:
                                _cache_data = fresh_data
                                _cache_timestamp = time.time()
                            record_snapshot(HISTORY_DB_PATH, fresh_data)
        except Exception:
            pass
        _polling_wake_event.wait(timeout=HISTORY_SAMPLE_INTERVAL_SECONDS)
        _polling_wake_event.clear()


def _start_history_collector() -> None:
    global _collector_started
    if os.getenv("DISABLE_BACKGROUND_COLLECTOR", "").strip() == "1":
        return
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return
    with _collector_lock:
        if _collector_started:
            return
        _collector_started = True
        thread = threading.Thread(target=_history_collector_loop, name="mist-history-collector", daemon=True)
        thread.start()


_start_history_collector()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
