from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, redirect, request, send_from_directory, session as flask_session
import requests

from history_store import init_history_db, query_history, record_snapshot
from nac_rejects import collect_nac_server_rejects
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
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "180"))
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
_cache_data: Optional[Dict[str, Any]] = None
_cache_timestamp: float = 0.0

_auth_lock = threading.Lock()
_pending_2fa: Dict[str, Dict[str, Any]] = {}
_login_attempts: Dict[str, List[float]] = {}
LOGIN_RATE_WINDOW_SECONDS = 300
LOGIN_RATE_MAX_ATTEMPTS = 15
TWO_FACTOR_CHALLENGE_TTL_SECONDS = 300
TWO_FACTOR_MAX_ATTEMPTS = 5


def mist_get_raw(
    session: requests.Session, path: str, params: Optional[Dict[str, Any]] = None
) -> Tuple[Any, Any]:
    """Strictly read-only GET helper returning (parsed JSON, response headers)."""
    url = f"{MIST_API_HOST}{path}"
    resp = session.get(url, params=params, timeout=20)
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


def fetch_site_telemetry(
    session: requests.Session, site: Dict[str, Any]
) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    site_id = site.get("id", "")
    site_name = site.get("name", site_id)
    clients: List[Dict[str, Any]] = []
    aps: List[Dict[str, Any]] = []
    warning: Optional[str] = None

    try:
        aps = mist_get_paginated(
            session,
            f"/api/v1/sites/{site_id}/stats/devices",
            params={"type": "ap"},
            limit=1000,
            send_page_params=True,
            dedup_keys=("mac", "id"),
        )
    except Exception as exc:
        warning = f"AP stats fetch failed for {site_name}: {exc}"

    site_ap_clients = sum(
        int(ap.get("num_clients") or 0)
        for ap in aps
        if str(ap.get("status") or "").lower() == "connected"
    )

    # Skip calling /stats/clients for sites that have 0 connected AP clients (saves ~15-20 Mist calls/refresh)
    if warning is None and site_ap_clients == 0:
        return site_id, [], aps, warning

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
    except Exception as exc:
        err = f"Clients fetch failed for {site_name}: {exc}"
        warning = f"{warning}; {err}" if warning else err

    return site_id, clients, aps, warning


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


def collect_mist_snapshot() -> Dict[str, Any]:
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise ValueError("MIST_ORG_ID and MIST_API_TOKEN must be configured in environment variables.")

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Token {MIST_API_TOKEN}",
            "Accept": "application/json",
        }
    )

    warnings: List[str] = []

    org_info = mist_get(session, f"/api/v1/orgs/{MIST_ORG_ID}")
    sites_raw = mist_get_paginated(
        session,
        f"/api/v1/orgs/{MIST_ORG_ID}/sites",
        limit=1000,
        send_page_params=True,
        dedup_keys=("id",),
    )

    site_map: Dict[str, Dict[str, Any]] = {
        s["id"]: s for s in sites_raw if isinstance(s, dict) and s.get("id")
    }

    site_clients: Dict[str, List[Dict[str, Any]]] = {}
    site_aps: Dict[str, List[Dict[str, Any]]] = {}

    if site_map:
        with ThreadPoolExecutor(max_workers=min(8, len(site_map))) as pool:
            futures = [
                pool.submit(fetch_site_telemetry, session, site)
                for site in site_map.values()
            ]
            for fut in as_completed(futures):
                site_id, clients, aps, warn = fut.result()
                site_clients[site_id] = clients
                site_aps[site_id] = aps
                if warn:
                    warnings.append(warn)

    site_clients = deduplicate_org_clients(site_map, site_clients)

    switches_online = 0
    switches_offline = 0
    offline_switches: List[Dict[str, Any]] = []
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
            status = str(sw.get("status") or "").lower()
            if status == "connected":
                switches_online += 1
                continue
            switches_offline += 1
            sid = sw.get("site_id", "")
            ip_stat = sw.get("ip_stat") if isinstance(sw.get("ip_stat"), dict) else {}
            sw_ip = str(sw.get("ip") or ip_stat.get("ip") or "").strip()
            offline_switches.append(
                {
                    "device_type": "Switch",
                    "name": sw.get("name") or sw.get("mac", "Unnamed Switch"),
                    "site_name": sw.get("site_name") or site_map.get(sid, {}).get("name", "Unassigned"),
                    "model": sw.get("model", ""),
                    "mac": sw.get("mac", ""),
                    "ip": sw_ip,
                    "version": sw.get("version", ""),
                    "last_seen": sw.get("last_seen"),
                    "status": status or "disconnected",
                }
            )
    except Exception as exc:
        warnings.append(f"Switch stats unavailable: {exc}")

    alarms: List[Dict[str, Any]] = []
    try:
        alarms_resp = mist_get(
            session,
            f"/api/v1/orgs/{MIST_ORG_ID}/alarms/search",
            params={"duration": "1d", "limit": 15},
        )
        raw_alarms = alarms_resp.get("results", []) if isinstance(alarms_resp, dict) else []
        for a in raw_alarms:
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
            ap_ip = ap.get("ip", "")
            ap_clients = int(ap.get("num_clients") or 0)

            if is_online:
                aps_online += 1
                site_aps_on += 1
                site_ap_clients += ap_clients
                total_ap_reported_clients += ap_clients
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
            "slow_aps_count": len(slow_aps),
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
        "slow_aps": slow_aps,
        "alarms": alarms,
        "warnings": warnings,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "read_only": True,
    }


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
        }
    )


@app.get("/api/stats")
def api_stats():
    global _cache_data, _cache_timestamp
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401

    force_refresh = request.args.get("refresh") == "1"
    now = time.time()

    with _cache_lock:
        cache_age = now - _cache_timestamp
        can_use_cache = _cache_data is not None and (
            (not force_refresh and cache_age < CACHE_TTL_SECONDS)
            or (force_refresh and cache_age < MIN_REFRESH_INTERVAL)
        )
        if can_use_cache:
            payload = dict(_cache_data)
            payload["cached"] = True
            payload["cache_age_seconds"] = int(cache_age)
            payload["auth_user"] = _current_user()
            resp = jsonify(payload)
            resp.headers["Cache-Control"] = "no-store"
            return resp

    try:
        fresh_data = collect_mist_snapshot()
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
    payload["auth_user"] = _current_user()
    resp = jsonify(payload)
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
_nac_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


@app.get("/api/nac-rejects")
def api_nac_rejects():
    if not _is_authenticated():
        return jsonify({"error": "Authentication required", "login_required": True}), 401
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return jsonify({"error": "Missing MIST_ORG_ID or MIST_API_TOKEN in environment."}), 500

    duration = "24h"
    force_refresh = request.args.get("refresh") == "1"
    now = time.time()

    with _nac_cache_lock:
        cached_entry = _nac_cache.get(duration)
        if cached_entry is not None:
            cached_ts, cached_payload = cached_entry
            age = now - cached_ts
            if (not force_refresh and age < CACHE_TTL_SECONDS) or (
                force_refresh and age < MIN_REFRESH_INTERVAL
            ):
                out = dict(cached_payload)
                out["cached"] = True
                out["cache_age_seconds"] = int(age)
                resp = jsonify(out)
                resp.headers["Cache-Control"] = "no-store"
                return resp

    site_name_map: Dict[str, str] = {}
    with _cache_lock:
        if isinstance(_cache_data, dict):
            for s in _cache_data.get("sites") or []:
                if isinstance(s, dict) and s.get("id"):
                    site_name_map[str(s["id"])] = str(s.get("name") or s["id"])

    session = requests.Session()
    session.headers.update({"Authorization": f"Token {MIST_API_TOKEN}", "Accept": "application/json"})
    try:
        fresh = collect_nac_server_rejects(
            session=session,
            api_host=MIST_API_HOST,
            org_id=MIST_ORG_ID,
            duration=duration,
            site_name_map=site_name_map or None,
        )
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Failed to query Mist NAC server rejects: {exc}"}), 502
    finally:
        session.close()

    fresh["fetched_at"] = datetime.now(timezone.utc).isoformat()
    with _nac_cache_lock:
        _nac_cache[duration] = (time.time(), fresh)

    out = dict(fresh)
    out["cached"] = False
    out["cache_age_seconds"] = 0
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

    session = requests.Session()
    session.headers.update({"Authorization": f"Token {MIST_API_TOKEN}", "Accept": "application/json"})
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

    session = requests.Session()
    session.headers.update({"Authorization": f"Token {MIST_API_TOKEN}", "Accept": "application/json"})
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
    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    return resp


_traffic_cache_lock = threading.Lock()
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
                out["cache_age_seconds"] = int(age)
                resp = jsonify(out)
                resp.headers["Cache-Control"] = "no-store"
                return resp

    session = requests.Session()
    session.headers.update({"Authorization": f"Token {MIST_API_TOKEN}", "Accept": "application/json"})
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
        return jsonify({"error": str(exc)}), 429
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        return jsonify({"error": f"Mist API returned HTTP {status}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Failed to query Mist traffic usage: {exc}"}), 502
    finally:
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
    out["cache_age_seconds"] = 0
    resp = jsonify(out)
    resp.headers["Cache-Control"] = "no-store"
    return resp


_collector_started = False
_collector_lock = threading.Lock()


def _history_collector_loop() -> None:
    """Continuously record Mist Wi-Fi client snapshots in the background so peaks are never missed."""
    global _cache_data, _cache_timestamp
    time.sleep(8)
    while True:
        try:
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
        time.sleep(HISTORY_SAMPLE_INTERVAL_SECONDS)


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
