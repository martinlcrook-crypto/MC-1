from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote
from zoneinfo import ZoneInfo

import requests

from client_lookup import get_wifi_client_detail, search_wifi_clients
from history_store import query_history
from nac_rejects import _mist_search_get, format_mac, mist_device_uuid_from_mac, normalize_mac


MAC_IN_MSG_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|\b[0-9a-fA-F]{12}\b")
IPV4_IN_MSG_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_IN_MSG_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
DOTTED_USER_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_\-]{1,24}\.[a-zA-Z][a-zA-Z0-9_\-]{1,24}\b")
UP_USER_RE = re.compile(r"\b(?:up\d{5,9}|[a-z]{2,4}\d{4,8})\b", re.IGNORECASE)
QUOTED_RE = re.compile(r'["\']([^"\']{2,80})["\']')
USER_CLAUSE_RE = re.compile(
    r"\b(?:did|is|was|has|does|for|with|by|of|user|username|client|lookup|find|locate|check|about|show(?:\s+me)?)\s+"
    r"([a-zA-Z0-9][a-zA-Z0-9._@\\\-]{2,64})\b",
    re.IGNORECASE,
)

STOP_ENTITIES = {
    "the", "this", "that", "these", "those", "there", "their", "they", "them", "any", "all",
    "what", "when", "where", "who", "which", "how", "many", "much", "some", "most", "top",
    "are", "were", "have", "been", "being", "from", "with", "into", "onto", "over", "under",
    "first", "last", "latest", "recent", "today", "yesterday", "morning", "tonight", "week",
    "month", "hour", "hours", "day", "days", "time", "now", "currently", "right", "live",
    "wifi", "wi-fi", "wireless", "wired", "eduroam", "visitor", "connect", "uop", "ssid",
    "switch", "switches", "ap", "aps", "access", "point", "points", "device", "devices",
    "site", "sites", "alarm", "alarms", "alert", "alerts", "critical", "warning", "warn",
    "down", "offline", "online", "connected", "disconnected", "hottest", "hot", "temp",
    "temperature", "thermal", "vc", "vcs", "virtual", "chassis", "member", "members",
    "linecard", "linecards", "pfe", "pfes", "fpc", "slow", "uplink", "uplinks", "nac",
    "reject", "rejects", "rejected", "denied", "peak", "peaks", "history", "traffic",
    "signal", "rssi", "busiest", "ex4000", "ex4100", "ex41000", "4000", "4100", "41000",
    "status", "health", "summary", "overview", "help", "me", "my", "our", "org", "mist",
    "user", "users", "client", "clients", "people", "anyone", "someone",
    "show", "list", "associated", "mac", "macs", "address", "addresses", "seen", "generated",
    "generate", "data", "bandwidth", "usage", "used", "using", "app", "apps", "application",
    "applications", "service", "services", "level", "levels", "insights", "total", "bytes",
    "instagram", "youtube", "tiktok", "netflix", "teams", "zoom", "spotify", "whatsapp",
    "facebook", "snapchat", "reddit", "apple", "icloud", "google", "gmail", "office365",
    "onedrive", "outlook", "discord", "twitch", "steam", "twitter", "chatgpt", "openai",
    "amazon", "bbc", "iplayer", "linkedin", "github", "dropbox", "slack", "webex", "xbox",
    "playstation", "microsoft", "ios", "android", "windows", "macos",
}

SSID_PATTERNS = [
    ("eduroam", re.compile(r"\beduroam\b", re.IGNORECASE)),
    ("UoP Visitor", re.compile(r"\buop[\s_\-]?visitor\b|\bvisitor\b", re.IGNORECASE)),
    ("UoP Connect", re.compile(r"\buop[\s_\-]?connect\b", re.IGNORECASE)),
]

FOLLOWUP_PRONOUN_RE = re.compile(
    r"\b(?:he|she|they|him|her|them|his|their|it|its|that user|that client|that device|those devices|same user|same device)\b",
    re.IGNORECASE,
)

# Canonical app name -> list of search tokens / aliases (lowercase)
KNOWN_APP_ALIASES: List[Tuple[str, Tuple[str, ...]]] = [
    ("Instagram", ("instagram",)),
    ("YouTube", ("youtube",)),
    ("TikTok", ("tiktok", "tik tok")),
    ("Microsoft Teams", ("microsoft teams", "ms teams", "msteams", "teams")),
    ("Zoom", ("zoom",)),
    ("Netflix", ("netflix",)),
    ("Spotify", ("spotify",)),
    ("WhatsApp", ("whatsapp", "whats app")),
    ("Facebook", ("facebook", "fb messenger")),
    ("Snapchat", ("snapchat",)),
    ("Reddit", ("reddit",)),
    ("iCloud", ("icloud",)),
    ("Apple", ("apple", "itunes", "app store")),
    ("Google", ("google drive", "google meet", "gmail", "google")),
    ("Microsoft 365", ("office 365", "office365", "microsoft 365", "o365", "onedrive", "sharepoint", "outlook")),
    ("Discord", ("discord",)),
    ("Twitch", ("twitch",)),
    ("Steam", ("steam",)),
    ("X / Twitter", ("twitter",)),
    ("ChatGPT / OpenAI", ("chatgpt", "openai")),
    ("Amazon", ("prime video", "amazon", "aws")),
    ("BBC iPlayer", ("iplayer", "bbc")),
    ("LinkedIn", ("linkedin",)),
    ("GitHub", ("github",)),
    ("Dropbox", ("dropbox",)),
    ("Slack", ("slack",)),
    ("Webex", ("webex",)),
    ("Xbox", ("xbox",)),
    ("PlayStation", ("playstation", "psn")),
]

DYNAMIC_APP_RE = re.compile(
    r"\bhow\s+much\s+([a-zA-Z0-9][a-zA-Z0-9 ._\-]{1,26}?)\s+(?:traffic|data|bandwidth|usage)\b",
    re.IGNORECASE,
)


def _fmt_bytes(num_bytes: Optional[float]) -> str:
    if num_bytes is None or not isinstance(num_bytes, (int, float)) or num_bytes < 0:
        return "0 B"
    val = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(round(val))} B"
            return f"{val:.2f} {unit}" if val < 10 else f"{val:.1f} {unit}"
        val /= 1024.0
    return f"{val:.1f} TB"


def _detect_app_query(message: str) -> Tuple[bool, Optional[str], Tuple[str, ...]]:
    """Return (wants_app_or_traffic, display_app_name, match_tokens)."""
    low = message.lower()
    for disp, aliases in KNOWN_APP_ALIASES:
        for alias in aliases:
            if re.search(r"\b" + re.escape(alias) + r"\b", low):
                # Use all meaningful aliases plus canonical name for matching Mist app labels
                tokens = tuple(dict.fromkeys([alias, disp.lower(), *[a for a in aliases if len(a) >= 3]]))
                return True, disp, tokens

    m_dyn = DYNAMIC_APP_RE.search(message)
    if m_dyn:
        cand = m_dyn.group(1).strip()
        cand_low = cand.lower()
        if cand_low not in ("total", "overall", "wifi", "wi-fi", "wireless", "wired", "network", "internet", "eduroam", "all", "app", "application"):
            return True, cand, (cand_low,)

    wants_general = any(
        k in low
        for k in (
            "app ", "apps", "application", "applications", "traffic", "bandwidth",
            "data usage", "how much data", "bytes", "generated", "top app", "service level",
        )
    )
    return wants_general, None, ()


def _has_explicit_time_window(message: str) -> bool:
    low = message.lower()
    return any(
        k in low
        for k in (
            "today", "this morning", "morning", "yesterday", "last hour", "past hour", "1h",
            "24h", "24 hours", "this week", "7d", "7 days", "past week", "this month", "30d", "30 days", "past month",
        )
    )


def _resolve_tz(tz_name: Optional[str], tz_offset_minutes: Optional[int]):
    if tz_name:
        try:
            return ZoneInfo(str(tz_name).strip())
        except Exception:
            pass
    if isinstance(tz_offset_minutes, (int, float)) and -840 <= tz_offset_minutes <= 840:
        # JS Date.getTimezoneOffset() returns minutes behind UTC (e.g. -60 for UTC+1, 0 for UTC)
        return timezone(timedelta(minutes=-int(tz_offset_minutes)))
    return timezone.utc


def _fmt_local_time(ts: Optional[int], tzinfo, include_date: bool = False) -> str:
    if not isinstance(ts, (int, float)) or ts <= 0:
        return "unknown time"
    dt = datetime.fromtimestamp(float(ts), tz=tzinfo)
    if include_date:
        return dt.strftime("%a %d %b at %H:%M:%S")
    return dt.strftime("%H:%M:%S")


def _fmt_rel_ago(ts: Optional[int], now_ts: int) -> str:
    if not isinstance(ts, (int, float)) or ts <= 0:
        return ""
    diff = max(0, int(now_ts - ts))
    if diff < 60:
        return f"{diff}s ago"
    mins = diff // 60
    if mins < 60:
        return f"{mins}m ago"
    hrs = mins // 60
    rem_m = mins % 60
    if hrs < 24:
        return f"{hrs}h {rem_m}m ago" if rem_m else f"{hrs}h ago"
    days = hrs // 24
    return f"{days}d {hrs % 24}h ago"


def _mist_base(org_id: str, ui_host: str) -> str:
    if not org_id or not ui_host:
        return ""
    return f"{ui_host.rstrip('/')}/admin/?org_id={quote(org_id, safe='')}"


def _link_site(org_id: str, ui_host: str, site_id: str, label: str) -> Dict[str, str]:
    base = _mist_base(org_id, ui_host)
    url = f"{base}#!dashboard/insights/site/{quote(site_id, safe='')}" if (base and site_id) else ""
    return {"label": label, "url": url, "kind": "site"}


def _link_switch(org_id: str, ui_host: str, site_id: str, sw_id: str, sw_mac: str, label: str) -> Dict[str, str]:
    base = _mist_base(org_id, ui_host)
    dev_id = sw_id or mist_device_uuid_from_mac(sw_mac)
    if base and site_id and dev_id:
        url = f"{base}#!switch/detail/{quote(dev_id, safe='')}/{quote(site_id, safe='')}"
    elif base and site_id:
        url = f"{base}#!switch/{quote(site_id, safe='')}"
    else:
        url = ""
    return {"label": label, "url": url, "kind": "switch"}


def _link_ap(org_id: str, ui_host: str, site_id: str, ap_id: str, ap_mac: str, label: str) -> Dict[str, str]:
    base = _mist_base(org_id, ui_host)
    dev_id = ap_id or mist_device_uuid_from_mac(ap_mac)
    if base and site_id and dev_id:
        url = f"{base}#!ap/detail/{quote(dev_id, safe='')}/{quote(site_id, safe='')}"
    elif base and site_id:
        url = f"{base}#!ap/{quote(site_id, safe='')}"
    else:
        url = ""
    return {"label": label, "url": url, "kind": "ap"}


def _link_client(org_id: str, ui_host: str, site_id: str, client_mac: str, label: str, kind: str = "client") -> Dict[str, str]:
    base = _mist_base(org_id, ui_host)
    mac_hex = normalize_mac(client_mac)
    if base and site_id and mac_hex:
        route = "wiredClient" if kind == "wired" else ("nacClient" if kind == "nac" else "client")
        url = f"{base}#!dashboard/insights/{route}/{quote(mac_hex, safe='')}/today/{quote(site_id, safe='')}"
    elif base and site_id:
        url = f"{base}#!clients/{quote(site_id, safe='')}"
    else:
        url = ""
    return {"label": label, "url": url, "kind": kind}


def _link_alerts(org_id: str, ui_host: str, site_id: str, label: str) -> Dict[str, str]:
    base = _mist_base(org_id, ui_host)
    if not base:
        url = ""
    elif site_id:
        url = f"{base}#!alerts/{quote(site_id, safe='')}"
    else:
        url = f"{base}#!alerts/org"
    return {"label": label, "url": url, "kind": "alerts"}


def _detect_ssid_filter(message: str) -> Optional[str]:
    for label, pat in SSID_PATTERNS:
        if pat.search(message):
            return label
    return None


def _detect_time_window(message: str, now_ts: int, tzinfo) -> Tuple[str, int, int, str]:
    """
    Return (mist_duration, window_start_ts, window_end_ts, human_label).
    """
    low = message.lower()
    now_dt = datetime.fromtimestamp(now_ts, tz=tzinfo)
    start_today = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)

    if "this morning" in low or "morning" in low and "yesterday" not in low:
        noon_today = start_today + timedelta(hours=12)
        end_dt = min(now_dt, noon_today) if now_dt > start_today else now_dt
        return "24h", int(start_today.timestamp()), int(max(end_dt.timestamp(), now_ts)), "this morning"
    if "yesterday" in low:
        start_y = start_today - timedelta(days=1)
        end_y = start_today - timedelta(seconds=1)
        return "7d", int(start_y.timestamp()), int(end_y.timestamp()), "yesterday"
    if "last hour" in low or "past hour" in low or "1h" in low:
        return "1h", now_ts - 3600, now_ts, "the last hour"
    if "today" in low or "24h" in low or "24 hours" in low:
        return "24h", int(start_today.timestamp()), now_ts, "today"
    if "this week" in low or "7d" in low or "7 days" in low or "past week" in low:
        return "7d", now_ts - 7 * 86400, now_ts, "the last 7 days"
    if "this month" in low or "30d" in low or "30 days" in low or "past month" in low:
        return "30d", now_ts - 30 * 86400, now_ts, "the last 30 days"
    return "24h", int(start_today.timestamp()), now_ts, "the last 24 hours"


def _find_mentioned_site(message: str, sites: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    low = message.lower()
    best = None
    best_len = 0
    for s in sites or []:
        name = str(s.get("name") or "").strip()
        if len(name) < 3:
            continue
        n_low = name.lower()
        if re.search(r"(?:^|\b)" + re.escape(n_low) + r"(?:\b|$)", low):
            if len(n_low) > best_len:
                best = s
                best_len = len(n_low)
    return best


def _extract_client_target(message: str, context: Dict[str, Any], sites: List[Dict[str, Any]]) -> Tuple[Optional[str], str]:
    """Return (target_query, detected_mode) or (None, '')."""
    m_mac = MAC_IN_MSG_RE.search(message)
    if m_mac:
        return m_mac.group(0), "mac"

    m_ip = IPV4_IN_MSG_RE.search(message)
    if m_ip:
        return m_ip.group(0), "ip"

    m_email = EMAIL_IN_MSG_RE.search(message)
    if m_email:
        return m_email.group(0), "username"

    m_quoted = QUOTED_RE.search(message)
    if m_quoted:
        q = m_quoted.group(1).strip()
        if q.lower() not in STOP_ENTITIES:
            return q, "auto"

    # Dotted usernames like nick.bull or martin.crook (excluding domain-like words)
    for m_dot in DOTTED_USER_RE.finditer(message):
        cand = m_dot.group(0).strip()
        parts = cand.lower().split(".")
        if parts[-1] in ("com", "org", "net", "uk", "edu", "gov", "io", "db", "py", "html"):
            continue
        if cand.lower() not in STOP_ENTITIES:
            return cand, "username"

    m_up = UP_USER_RE.search(message)
    if m_up:
        cand = m_up.group(0).strip()
        if not re.match(r"^(?:ex|ap|sw|vc)?\d{4,5}$", cand, re.IGNORECASE) and cand.lower() not in STOP_ENTITIES:
            return cand, "username"

    # Clause patterns: "when did <name> connect", "find <name>", "lookup <name>"
    site_names_low = {str(s.get("name") or "").strip().lower() for s in (sites or [])}
    for m_cl in USER_CLAUSE_RE.finditer(message):
        cand = m_cl.group(1).strip().rstrip("?!.,;:")
        cand_low = cand.lower()
        if cand_low in STOP_ENTITIES or cand_low in site_names_low:
            continue
        if len(cand) >= 3:
            return cand, "auto"

    # Follow-up pronoun referencing the previous user/client in conversation
    if FOLLOWUP_PRONOUN_RE.search(message) and context.get("last_client_query"):
        return str(context["last_client_query"]), str(context.get("last_client_mode") or "auto")

    return None, ""


def _find_mentioned_device(message: str, snapshot: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Check if message explicitly mentions a known VC, switch, or AP from cached snapshot."""
    low = message.lower()
    for vc in snapshot.get("vc_temps") or []:
        name = str(vc.get("name") or "").strip()
        if len(name) >= 4 and name.lower() in low:
            return "vc", vc
    for sw in snapshot.get("offline_switches") or []:
        name = str(sw.get("name") or "").strip()
        if len(name) >= 4 and name.lower() in low:
            return "switch_down", sw
    for ap in (snapshot.get("top_aps") or []) + (snapshot.get("offline_aps") or []) + (snapshot.get("slow_aps") or []):
        name = str(ap.get("name") or "").strip()
        if len(name) >= 4 and name.lower() in low:
            return "ap", ap
    return None


def _parse_apps_payload(payload: Any) -> List[Dict[str, Any]]:
    """Normalize Mist Insights top-app-by-bytes responses across classic and multi-metric schemas."""
    raw_items: List[Any] = []
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            raw_items = payload["results"]
        elif isinstance(payload.get("top-app-by-bytes"), list):
            raw_items = payload["top-app-by-bytes"]
        elif isinstance(payload.get("top-app-by-bytes"), dict) and isinstance(payload["top-app-by-bytes"].get("results"), list):
            raw_items = payload["top-app-by-bytes"]["results"]
        elif isinstance(payload.get("apps"), list):
            raw_items = payload["apps"]

    out: List[Dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("app")
            or item.get("name")
            or item.get("app_name")
            or item.get("application")
            or item.get("service")
            or item.get("key")
            or ""
        ).strip()
        if not name:
            continue
        rx_raw = item.get("rx_bytes")
        tx_raw = item.get("tx_bytes")
        rx_b = float(rx_raw) if isinstance(rx_raw, (int, float)) and rx_raw >= 0 else None
        tx_b = float(tx_raw) if isinstance(tx_raw, (int, float)) and tx_raw >= 0 else None
        tot_raw = item.get("total_bytes")
        if tot_raw is None:
            tot_raw = item.get("bytes")
        if tot_raw is None:
            tot_raw = item.get("usage")
        if isinstance(tot_raw, (int, float)) and tot_raw >= 0:
            tot_b = float(tot_raw)
        elif rx_b is not None or tx_b is not None:
            tot_b = (rx_b or 0.0) + (tx_b or 0.0)
        else:
            tot_b = 0.0
        out.append({
            "app": name,
            "total_bytes": tot_b,
            "rx_bytes": rx_b,
            "tx_bytes": tx_b,
            "num_clients": item.get("num_clients"),
        })
    return out


def _fetch_client_app_usage(
    session: requests.Session,
    api_host: str,
    site_id: str,
    mac_raw: str,
    start_ts: int,
    end_ts: int,
) -> List[Dict[str, Any]]:
    """Query Mist Client Insights (Monitor > Service Levels > Insights) top-app-by-bytes for a client MAC."""
    if not site_id or not mac_raw:
        return []
    mac_hex = normalize_mac(mac_raw)
    if not mac_hex:
        return []

    attempts = [
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/client/{mac_hex}/top-app-by-bytes",
            {"start": str(start_ts), "end": str(end_ts), "limit": "100"},
        ),
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/client/{mac_hex}",
            {"metrics": "top-app-by-bytes", "start": str(start_ts), "end": str(end_ts), "limit": "100"},
        ),
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/client/{mac_hex}/stats",
            {"metrics": "top-app-by-bytes", "start": str(start_ts), "end": str(end_ts), "limit": "100"},
        ),
    ]
    for url, params in attempts:
        try:
            resp = session.get(url, params=params, timeout=15)
            if resp.status_code == 429:
                return []
            if resp.status_code != 200:
                continue
            payload = resp.json()
            parsed = _parse_apps_payload(payload)
            if parsed:
                return parsed
            # If the classic endpoint returned HTTP 200 with an explicit empty results list,
            # no need to burn extra API calls retrying the same metric.
            if isinstance(payload, dict) and isinstance(payload.get("results"), list) and len(payload["results"]) == 0:
                return []
        except Exception:
            continue
    return []


def _extract_bytes_from_insight(payload: Any, fallback_interval_sec: int = 600) -> Tuple[float, float, float, bool]:
    """
    Parse total/rx/tx bytes from any Mist Client Insights response shape:
      - {"rx_bytes": [...], "tx_bytes": [...], "bytes": [...]}
      - {"results": [185, 197, ...]}  (single-metric /bytes endpoint)
      - {"results": [{"rx_bytes": ..., "tx_bytes": ..., "bytes": ...}, ...]}
      - {"rx_bps": [...], "tx_bps": [...]} (last-resort bps * interval / 8 conversion)
    Returns (total_bytes, rx_bytes, tx_bytes, has_rxtx).
    """
    def _sum_num_or_list(val: Any) -> float:
        if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
            return float(val)
        if isinstance(val, list):
            return sum(float(v) for v in val if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0)
        return 0.0

    if isinstance(payload, list):
        # List of numbers or dicts
        num_sum = _sum_num_or_list(payload)
        if num_sum > 0:
            return num_sum, 0.0, 0.0, False
        rx_s = tx_s = tot_s = 0.0
        for row in payload:
            if not isinstance(row, dict):
                continue
            r = _sum_num_or_list(row.get("rx_bytes"))
            t = _sum_num_or_list(row.get("tx_bytes"))
            b = _sum_num_or_list(row.get("total_bytes") if row.get("total_bytes") is not None else row.get("bytes"))
            rx_s += r
            tx_s += t
            tot_s += b if b > 0 else (r + t)
        if rx_s > 0 or tx_s > 0:
            return max(tot_s, rx_s + tx_s), rx_s, tx_s, True
        return tot_s, 0.0, 0.0, False

    if not isinstance(payload, dict):
        return 0.0, 0.0, 0.0, False

    rx_sum = _sum_num_or_list(payload.get("rx_bytes"))
    tx_sum = _sum_num_or_list(payload.get("tx_bytes"))
    bytes_sum = _sum_num_or_list(payload.get("bytes"))
    if rx_sum > 0 or tx_sum > 0:
        return max(bytes_sum, rx_sum + tx_sum), rx_sum, tx_sum, True
    if bytes_sum > 0:
        return bytes_sum, 0.0, 0.0, False

    # Single-metric endpoints return {"results": [n1, n2, ...]} or {"results": [{...}]}
    res_val = payload.get("results")
    if isinstance(res_val, list) and res_val:
        t_r, rx_r, tx_r, has_rt = _extract_bytes_from_insight(res_val, fallback_interval_sec=fallback_interval_sec)
        if t_r > 0:
            return t_r, rx_r, tx_r, has_rt

    # Last-resort: convert rx_bps / tx_bps buckets into approximate bytes
    rx_bps = payload.get("rx_bps") if isinstance(payload.get("rx_bps"), list) else []
    tx_bps = payload.get("tx_bps") if isinstance(payload.get("tx_bps"), list) else []
    if rx_bps or tx_bps:
        iv = payload.get("interval")
        iv_sec = int(iv) if isinstance(iv, (int, float)) and iv > 0 else fallback_interval_sec
        rx_est = sum(float(v) * iv_sec / 8.0 for v in rx_bps if isinstance(v, (int, float)) and v > 0)
        tx_est = sum(float(v) * iv_sec / 8.0 for v in tx_bps if isinstance(v, (int, float)) and v > 0)
        if rx_est > 0 or tx_est > 0:
            return rx_est + tx_est, rx_est, tx_est, True

    return 0.0, 0.0, 0.0, False


def _fetch_client_total_bytes(
    session: requests.Session,
    api_host: str,
    site_id: str,
    mac_raw: str,
    start_ts: int,
    end_ts: int,
    is_wired_only: bool = False,
) -> Tuple[float, float, float, bool]:
    """
    Return (total_bytes, rx_bytes, tx_bytes, has_rxtx) from Mist historical Client Insights
    covering the full [start_ts, end_ts] window (works for both online AND disconnected clients).
    """
    mac_hex = normalize_mac(mac_raw)
    if not site_id or not mac_hex:
        return 0.0, 0.0, 0.0, False

    span_sec = max(60, int(end_ts - start_ts))
    pref_interval = "600" if span_sec <= 86400 else "3600"
    pref_iv_int = int(pref_interval)
    scope_prefix = "wired-client" if is_wired_only else "client"

    attempts: List[Tuple[str, Dict[str, str]]] = [
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/{scope_prefix}/{mac_hex}/stats",
            {"metrics": "rx_bytes,tx_bytes,bytes", "start": str(start_ts), "end": str(end_ts), "interval": pref_interval},
        ),
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/{scope_prefix}/{mac_hex}",
            {"metrics": "rx_bytes,tx_bytes,bytes", "start": str(start_ts), "end": str(end_ts)},
        ),
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/{scope_prefix}/{mac_hex}/bytes",
            {"start": str(start_ts), "end": str(end_ts)},
        ),
    ]
    if is_wired_only:
        # Also try generic /insights/client/{mac} in case Mist aggregates wired stats there
        attempts.append((
            f"{api_host}/api/v1/sites/{site_id}/insights/client/{mac_hex}/stats",
            {"metrics": "rx_bytes,tx_bytes,bytes", "start": str(start_ts), "end": str(end_ts), "interval": pref_interval},
        ))

    for idx, (url, params) in enumerate(attempts):
        try:
            resp = session.get(url, params=params, timeout=15)
            if resp.status_code == 429:
                return 0.0, 0.0, 0.0, False
            if resp.status_code == 400 and params.get("interval") == "600":
                retry_params = dict(params)
                retry_params["interval"] = "3600"
                resp = session.get(url, params=retry_params, timeout=15)
                if resp.status_code == 429:
                    return 0.0, 0.0, 0.0, False
            if resp.status_code != 200:
                continue
            tot, rx_b, tx_b, has_rt = _extract_bytes_from_insight(resp.json(), fallback_interval_sec=pref_iv_int)
            if tot > 0:
                return tot, rx_b, tx_b, has_rt
        except Exception:
            continue

    # Last-resort single-metric rx_bytes + tx_bytes calls (for older Mist clusters where /stats omits them)
    rx_single = tx_single = 0.0
    got_any = False
    for metric_name in ("rx_bytes", "tx_bytes"):
        try:
            r = session.get(
                f"{api_host}/api/v1/sites/{site_id}/insights/{scope_prefix}/{mac_hex}/{metric_name}",
                params={"start": str(start_ts), "end": str(end_ts)},
                timeout=12,
            )
            if r.status_code == 200:
                t_m, _, _, _ = _extract_bytes_from_insight(r.json(), fallback_interval_sec=pref_iv_int)
                if t_m > 0:
                    got_any = True
                    if metric_name == "rx_bytes":
                        rx_single = t_m
                    else:
                        tx_single = t_m
        except Exception:
            continue
    if got_any:
        return rx_single + tx_single, rx_single, tx_single, True

    return 0.0, 0.0, 0.0, False


def _fetch_site_app_usage(
    session: requests.Session,
    api_host: str,
    site_id: str,
    start_ts: int,
    end_ts: int,
) -> List[Dict[str, Any]]:
    """Query Mist Site Insights top-app-by-bytes for a site."""
    if not site_id:
        return []
    for url, params in (
        (
            f"{api_host}/api/v1/sites/{site_id}/insights/top-app-by-bytes",
            {"start": str(start_ts), "end": str(end_ts), "limit": "100"},
        ),
        (
            f"{api_host}/api/v1/sites/{site_id}/insights",
            {"metrics": "top-app-by-bytes", "start": str(start_ts), "end": str(end_ts), "limit": "100"},
        ),
    ):
        try:
            resp = session.get(url, params=params, timeout=15)
            if resp.status_code != 200:
                continue
            parsed = _parse_apps_payload(resp.json())
            if parsed:
                return parsed
        except Exception:
            continue
    return []


def _device_short_label(dev: Dict[str, Any]) -> str:
    """Build a concise human-readable device descriptor (hostname + OS/model/mfg)."""
    host = str(dev.get("hostname") or "").strip()
    model = str(dev.get("model") or "").strip()
    family = str(dev.get("family") or "").strip()
    os_val = str(dev.get("os") or "").strip()
    mfg = str(dev.get("manufacture") or "").strip()

    hw_parts: List[str] = []
    for cand in (model, family, os_val, mfg):
        if cand and cand.lower() not in (host.lower(),) and all(cand.lower() not in p.lower() for p in hw_parts):
            hw_parts.append(cand)
            if len(hw_parts) >= 2:
                break

    hw_str = " / ".join(hw_parts)
    if host and hw_str:
        return f"{host} ({hw_str})"
    return host or hw_str or dev.get("mac") or "Unknown Device"


def _discover_all_user_devices(
    session: requests.Session,
    api_host: str,
    org_id: str,
    target: str,
    mode: str,
    duration: str,
    site_name_map: Dict[str, str],
) -> List[Dict[str, Any]]:
    """
    Discover ALL unique device MAC addresses associated with a user/target across
    Mist Wi-Fi clients/sessions, Wired clients, and NAC clients in parallel.
    """
    mist_dur = "1d" if duration in ("1h", "24h", "1d") else ("30d" if duration == "30d" else "7d")
    wild_q = target if "*" in target else f"*{target}*"

    def fetch_wifi():
        try:
            res = search_wifi_clients(
                session=session,
                api_host=api_host,
                org_id=org_id,
                query=target,
                mode=mode,
                duration="24h" if mist_dur == "1d" else mist_dur,
                site_name_map=site_name_map,
            )
            return res.get("clients") or []
        except Exception:
            return []

    def fetch_wired():
        params: Dict[str, Any] = {"duration": mist_dur, "limit": 100}
        if mode == "mac":
            params["mac"] = normalize_mac(target)
        elif mode == "ip":
            params["ip"] = target
        else:
            params["text"] = wild_q
        try:
            return _mist_search_get(
                session, api_host, f"/api/v1/orgs/{org_id}/wired_clients/search", params, max_pages=1
            )
        except Exception:
            return []

    def fetch_nac():
        params: Dict[str, Any] = {"duration": mist_dur, "limit": 100}
        if mode == "mac":
            params["mac"] = normalize_mac(target)
        else:
            params["text"] = wild_q
        try:
            return _mist_search_get(
                session, api_host, f"/api/v1/orgs/{org_id}/nac_clients/search", params, max_pages=1
            )
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_wifi = pool.submit(fetch_wifi)
        f_wired = pool.submit(fetch_wired)
        f_nac = pool.submit(fetch_nac)
        wifi_rows = f_wifi.result()
        wired_rows = f_wired.result()
        nac_rows = f_nac.result()

    by_mac: Dict[str, Dict[str, Any]] = {}

    def ensure_dev(mac_norm: str) -> Dict[str, Any]:
        rec = by_mac.get(mac_norm)
        if rec is None:
            rec = {
                "mac": format_mac(mac_norm),
                "mac_raw": mac_norm,
                "hostname": "",
                "username": "",
                "os": "",
                "family": "",
                "model": "",
                "manufacture": "",
                "sources": [],
                "ssid": "",
                "port_id": "",
                "vlan": None,
                "ip": "",
                "site_id": "",
                "site_name": "Unknown Site",
                "seen_site_ids": [],
                "ap_name": "",
                "ap_mac": "",
                "band": "",
                "rssi": None,
                "online": False,
                "first_seen": 0,
                "last_seen": 0,
            }
            by_mac[mac_norm] = rec
        return rec

    def _first_str(*vals: Any) -> str:
        for v in vals:
            if isinstance(v, list):
                for x in v:
                    s = str(x or "").strip()
                    if s:
                        return s
            else:
                s = str(v or "").strip()
                if s:
                    return s
        return ""

    for c in wifi_rows:
        mac_norm = normalize_mac(c.get("mac_raw") or c.get("mac"))
        if not mac_norm:
            continue
        rec = ensure_dev(mac_norm)
        if "Wi-Fi" not in rec["sources"]:
            rec["sources"].append("Wi-Fi")
        rec["online"] = rec["online"] or bool(c.get("online"))
        ts_last = int(c.get("last_seen") or 0)
        ts_first = int(c.get("first_seen") or ts_last or 0)
        if ts_first > 0 and (rec["first_seen"] <= 0 or ts_first < rec["first_seen"]):
            rec["first_seen"] = ts_first
        if ts_last >= rec["last_seen"]:
            rec["last_seen"] = ts_last
            if c.get("site_id"):
                rec["site_id"] = str(c["site_id"])
                rec["site_name"] = str(c.get("site_name") or site_name_map.get(rec["site_id"]) or rec["site_id"])
            if c.get("ap_name"):
                rec["ap_name"] = str(c["ap_name"])
            if c.get("ap_mac"):
                rec["ap_mac"] = str(c["ap_mac"])
            if c.get("ssid"):
                rec["ssid"] = str(c["ssid"])
            if c.get("ip"):
                rec["ip"] = str(c["ip"])
            if c.get("rssi") is not None:
                rec["rssi"] = c["rssi"]
            if c.get("band"):
                rec["band"] = str(c["band"])
        for sid in (c.get("seen_site_ids") or [c.get("site_id")]):
            s_str = str(sid or "").strip()
            if s_str and s_str not in rec["seen_site_ids"]:
                rec["seen_site_ids"].append(s_str)
        for fld in ("hostname", "username", "os", "family", "model", "manufacture", "ssid", "ip", "ap_name", "ap_mac"):
            if not rec.get(fld) and c.get(fld):
                rec[fld] = str(c[fld])
        if rec["vlan"] is None and c.get("vlan") is not None:
            rec["vlan"] = c["vlan"]

    for w in wired_rows:
        mac_norm = normalize_mac(w.get("mac"))
        if not mac_norm:
            continue
        rec = ensure_dev(mac_norm)
        if "Wired" not in rec["sources"]:
            rec["sources"].append("Wired")
        sid = str(w.get("site_id") or "")
        if sid and sid not in rec["seen_site_ids"]:
            rec["seen_site_ids"].append(sid)
        ts = int(float(w.get("timestamp") or 0))
        if ts > 0 and (rec["first_seen"] <= 0 or ts < rec["first_seen"]):
            rec["first_seen"] = ts
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts
            if sid:
                rec["site_id"] = sid
                rec["site_name"] = site_name_map.get(sid) or sid
        for fld, val in (
            ("hostname", _first_str(w.get("hostname"), w.get("dhcp_hostname"))),
            ("username", _first_str(w.get("username"), w.get("last_username"))),
            ("ip", _first_str(w.get("ip"), w.get("last_ip"))),
            ("port_id", _first_str(w.get("port_id"))),
            ("manufacture", _first_str(w.get("manufacture"), w.get("mfg"))),
            ("os", _first_str(w.get("os"))),
        ):
            if not rec.get(fld) and val:
                rec[fld] = val
        if not rec["site_id"] and sid:
            rec["site_id"] = sid
            rec["site_name"] = site_name_map.get(sid) or sid
        if rec["vlan"] is None and w.get("vlan") is not None:
            rec["vlan"] = w["vlan"]

    for n in nac_rows:
        mac_norm = normalize_mac(n.get("mac"))
        if not mac_norm:
            continue
        rec = ensure_dev(mac_norm)
        nac_type = str(n.get("type") or "").lower()
        src_lbl = "Wired" if "wired" in nac_type else ("Wi-Fi" if "wire" in nac_type else "NAC")
        if src_lbl not in rec["sources"]:
            rec["sources"].append(src_lbl)
        sid = str(n.get("site_id") or "")
        if sid and sid not in rec["seen_site_ids"]:
            rec["seen_site_ids"].append(sid)
        ts = int(float(n.get("timestamp") or n.get("last_seen") or 0))
        if ts > 0 and (rec["first_seen"] <= 0 or ts < rec["first_seen"]):
            rec["first_seen"] = ts
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts
            if sid:
                rec["site_id"] = sid
                rec["site_name"] = site_name_map.get(sid) or sid
        for fld, val in (
            ("hostname", _first_str(n.get("hostname"), n.get("last_hostname"))),
            ("username", _first_str(n.get("username"), n.get("last_username"), n.get("idp_user"))),
            ("ssid", _first_str(n.get("ssid"), n.get("last_ssid"))),
            ("os", _first_str(n.get("os"))),
            ("family", _first_str(n.get("family"))),
            ("model", _first_str(n.get("model"))),
            ("manufacture", _first_str(n.get("mfg"), n.get("manufacture"))),
        ):
            if not rec.get(fld) and val:
                rec[fld] = val
        if not rec["site_id"] and sid:
            rec["site_id"] = sid
            rec["site_name"] = site_name_map.get(sid) or sid

    devices = list(by_mac.values())
    devices.sort(key=lambda d: (0 if d["online"] else 1, -int(d.get("last_seen") or 0), d["mac"]))
    return devices


def _answer_user_devices(
    message: str,
    target: str,
    mode: str,
    session: requests.Session,
    api_host: str,
    ui_host: str,
    org_id: str,
    site_name_map: Dict[str, str],
    tzinfo,
    now_ts: int,
) -> Dict[str, Any]:
    """List ALL unique device MAC addresses associated with a user (with exact times seen)."""
    explicit_win = _has_explicit_time_window(message)
    mist_dur, win_start, win_end, win_label = _detect_time_window(message, now_ts, tzinfo)
    ssid_filter = _detect_ssid_filter(message)

    # When no narrow window is specified (e.g. "show the devices associated with nick.bull"),
    # search the full 30 days across Wi-Fi + Wired + NAC to surface every MAC address Mist has seen.
    discover_dur = "7d" if (explicit_win and mist_dur in ("1h", "24h", "7d")) else "30d"
    devices = _discover_all_user_devices(
        session=session,
        api_host=api_host,
        org_id=org_id,
        target=target,
        mode=mode,
        duration=discover_dur,
        site_name_map=site_name_map,
    )

    if not devices:
        return {
            "reply": (
                f"I searched Mist across Wi-Fi, Wired, and NAC clients for **`{target}`** (last {discover_dur}) "
                f"and didn't find any associated device MAC addresses."
            ),
            "highlights": [{"label": "Devices Found", "value": "0"}],
            "links": [],
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    display_user = next((d["username"] for d in devices if d.get("username")), target)

    # If the user asked for a specific time window (e.g. "today"), enrich up to 8 Wi-Fi devices
    # with events & sessions in parallel so we have exact First Seen & Last Seen inside that window.
    detail_by_mac: Dict[str, Dict[str, Any]] = {}
    if explicit_win:
        candidates = [
            d for d in devices
            if "Wi-Fi" in d["sources"] and (d.get("online") or (d.get("last_seen") or 0) >= win_start - 3600)
        ][:8]
        if not candidates:
            candidates = [d for d in devices if "Wi-Fi" in d["sources"]][:4]

        def fetch_det(dev_item: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
            try:
                det = get_wifi_client_detail(
                    session=session,
                    api_host=api_host,
                    org_id=org_id,
                    mac=dev_item["mac"],
                    site_id=dev_item.get("site_id") or "",
                    duration="24h" if mist_dur in ("1h", "24h") else mist_dur,
                    site_name_map=site_name_map,
                )
                return dev_item["mac_raw"], det
            except Exception:
                return dev_item["mac_raw"], None

        if candidates:
            with ThreadPoolExecutor(max_workers=min(6, len(candidates))) as pool:
                for m_raw, det in pool.map(fetch_det, candidates):
                    if det:
                        detail_by_mac[m_raw] = det

    # Compute window-scoped first_seen / last_seen for each device
    active_in_window: List[Dict[str, Any]] = []
    older_outside: List[Dict[str, Any]] = []

    for d in devices:
        if ssid_filter and d.get("ssid") and ssid_filter.lower() not in d["ssid"].lower():
            continue

        det = detail_by_mac.get(d["mac_raw"])
        win_ts_list: List[int] = []
        if det:
            prof = det.get("profile") or {}
            if prof.get("online"):
                d["online"] = True
            for fld in ("hostname", "username", "os", "family", "model", "manufacture", "ssid", "ip", "ap_name"):
                if not d.get(fld) and prof.get(fld):
                    d[fld] = str(prof[fld])
            for ev in det.get("events") or []:
                ts = ev.get("timestamp") or 0
                if isinstance(ts, (int, float)) and win_start <= ts <= win_end:
                    win_ts_list.append(int(ts))
            for sess in det.get("sessions") or []:
                s_ts = sess.get("timestamp") or 0
                s_dur = sess.get("duration") or 0
                if isinstance(s_ts, (int, float)) and s_ts > 0:
                    s_start = int(s_ts - s_dur) if (isinstance(s_dur, (int, float)) and s_dur > 0) else int(s_ts)
                    # Session overlaps [win_start, win_end]
                    if s_ts >= win_start and s_start <= win_end:
                        win_ts_list.append(max(s_start, win_start))
                        win_ts_list.append(min(int(s_ts), win_end))
            prof_ls = prof.get("last_seen") or 0
            if isinstance(prof_ls, (int, float)) and win_start <= prof_ls <= win_end:
                win_ts_list.append(int(prof_ls))
            if prof.get("online") and isinstance(prof.get("uptime"), (int, float)) and prof["uptime"] > 0:
                u_start = int(now_ts - prof["uptime"])
                if u_start <= win_end:
                    win_ts_list.append(max(u_start, win_start))
                    win_ts_list.append(min(now_ts, win_end))

        if not win_ts_list:
            ls = int(d.get("last_seen") or 0)
            fs = int(d.get("first_seen") or ls)
            if ls >= win_start and ls <= win_end:
                win_ts_list.append(ls)
            if fs >= win_start and fs <= win_end:
                win_ts_list.append(fs)
            if d.get("online") and win_end >= now_ts - 300:
                win_ts_list.append(now_ts)

        row_copy = dict(d)
        if explicit_win:
            if win_ts_list:
                row_copy["win_first_seen"] = min(win_ts_list)
                row_copy["win_last_seen"] = max(win_ts_list)
                active_in_window.append(row_copy)
            else:
                older_outside.append(row_copy)
        else:
            row_copy["win_first_seen"] = int(d.get("first_seen") or 0)
            row_copy["win_last_seen"] = int(d.get("last_seen") or 0)
            active_in_window.append(row_copy)

    if explicit_win and not active_in_window:
        # Show all older MACs so the answer is still immediately useful
        older_lines = []
        links = []
        for d in older_outside[:10]:
            src_txt = "/".join(d["sources"]) or "Client"
            conn = f"{src_txt} · {d['ssid']}" if d.get("ssid") else (f"{src_txt} · {d['port_id']}" if d.get("port_id") else src_txt)
            older_lines.append(
                f"- **`{d['mac']}`** — {_device_short_label(d)} · {conn} · **{d['site_name']}** · "
                f"last seen **{_fmt_local_time(d.get('last_seen'), tzinfo, include_date=True)}**"
            )
            if d.get("site_id"):
                kind = "wired" if d["sources"] == ["Wired"] else ("nac" if d["sources"] == ["NAC"] else "client")
                links.append(_link_client(org_id, ui_host, d["site_id"], d["mac"], f"{d['hostname'] or d['mac']}", kind=kind))
        return {
            "reply": (
                f"No devices for **{display_user}** were seen **{win_label}**, "
                f"but Mist has **{len(older_outside)}** associated MAC address(es) from the last {discover_dur}:\n"
                + "\n".join(older_lines)
            ),
            "highlights": [
                {"label": f"Seen {win_label}", "value": "0"},
                {"label": f"Total MACs ({discover_dur})", "value": str(len(older_outside))},
            ],
            "links": links[:5],
            "context": {"last_client_query": target, "last_client_mode": mode},
            "action_tab": "tab-client-lookup",
        }

    # Format full breakdown of every matched MAC address
    include_date = not (explicit_win and win_label in ("today", "this morning", "the last hour"))
    lines: List[str] = []
    links: List[Dict[str, str]] = []
    online_count = sum(1 for d in active_in_window if d.get("online"))
    wifi_cnt = sum(1 for d in active_in_window if "Wi-Fi" in d["sources"])
    wired_cnt = sum(1 for d in active_in_window if "Wired" in d["sources"])

    for d in active_in_window[:25]:
        status_tag = "**Online**" if d.get("online") else "Offline"
        src_txt = "/".join(d["sources"]) or "Client"
        if d.get("ssid"):
            conn = f"{src_txt} · **{d['ssid']}**"
        elif d.get("port_id"):
            conn = f"{src_txt} · port `{d['port_id']}`"
        else:
            conn = src_txt

        fs = d.get("win_first_seen") or 0
        ls = d.get("win_last_seen") or 0
        if explicit_win and fs > 0 and ls > 0 and abs(ls - fs) >= 60:
            time_part = f"first **{_fmt_local_time(fs, tzinfo, include_date=include_date)}**, last **{_fmt_local_time(ls, tzinfo, include_date=include_date)}**"
        elif ls > 0:
            time_part = f"seen **{_fmt_local_time(ls, tzinfo, include_date=include_date)}**"
        elif fs > 0:
            time_part = f"seen **{_fmt_local_time(fs, tzinfo, include_date=include_date)}**"
        else:
            time_part = "time unknown"

        loc_part = f"**{d['site_name']}**" + (f" ({d['ap_name']})" if d.get("ap_name") else "")
        ip_part = f" · IP `{d['ip']}`" if d.get("ip") else ""
        lines.append(
            f"- **`{d['mac']}`** — {_device_short_label(d)} · {status_tag} · {conn} · {loc_part}{ip_part} · {time_part}"
        )
        if d.get("site_id") and len(links) < 5:
            kind = "wired" if d["sources"] == ["Wired"] else ("nac" if d["sources"] == ["NAC"] else "client")
            links.append(_link_client(org_id, ui_host, d["site_id"], d["mac"], f"{d.get('hostname') or d['mac']}", kind=kind))

    more_note = f"\n…and **{len(active_in_window) - 25}** more MACs." if len(active_in_window) > 25 else ""
    older_note = ""
    if explicit_win and older_outside:
        older_preview = ", ".join(f"`{x['mac']}` ({_device_short_label(x)})" for x in older_outside[:4])
        extra = f" +{len(older_outside) - 4} more" if len(older_outside) > 4 else ""
        older_note = f"\nAlso associated in the last {discover_dur} (not seen {win_label}): **{len(older_outside)}** other MAC(s) — {older_preview}{extra}."

    scope_txt = f"**{win_label}**" if explicit_win else f"over the last **{discover_dur}**"
    header = (
        f"Found **{len(active_in_window)}** device MAC address(es) for **{display_user}** {scope_txt} "
        f"({online_count} currently online):"
    )

    return {
        "reply": header + "\n" + "\n".join(lines) + more_note + older_note,
        "highlights": [
            {"label": "Devices (MACs)", "value": str(len(active_in_window))},
            {"label": "Online Now", "value": str(online_count)},
            {"label": "Wi-Fi / Wired", "value": f"{wifi_cnt} / {wired_cnt}"},
            {"label": "Window", "value": win_label if explicit_win else f"Last {discover_dur}"},
        ],
        "links": links,
        "context": {"last_client_query": target, "last_client_mode": mode},
        "action_tab": "tab-client-lookup",
    }


def _answer_user_app_traffic(
    message: str,
    target: str,
    mode: str,
    requested_app: Optional[str],
    app_tokens: Tuple[str, ...],
    session: requests.Session,
    api_host: str,
    ui_host: str,
    org_id: str,
    site_name_map: Dict[str, str],
    tzinfo,
    now_ts: int,
) -> Dict[str, Any]:
    """Query Mist Client Insights (Monitor > Service Levels > Insights) application traffic across all user MACs."""
    mist_dur, win_start, win_end, win_label = _detect_time_window(message, now_ts, tzinfo)
    discover_dur = "7d" if mist_dur in ("1h", "24h", "7d") else "30d"

    devices = _discover_all_user_devices(
        session=session,
        api_host=api_host,
        org_id=org_id,
        target=target,
        mode=mode,
        duration=discover_dur,
        site_name_map=site_name_map,
    )
    if not devices:
        return {
            "reply": (
                f"I searched Mist for **`{target}`** (last {discover_dur}) and couldn't find any client devices "
                f"to pull application traffic for."
            ),
            "highlights": [],
            "links": [],
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    display_user = next((d["username"] for d in devices if d.get("username")), target)

    # Pick ALL devices active since start of window (including now-disconnected devices!)
    # Sort by most recently seen (not online-only) so recently disconnected high-traffic devices are never dropped.
    recent_devs = sorted(devices, key=lambda d: (-int(d.get("last_seen") or 0), 0 if d.get("online") else 1, d["mac"]))
    active_devs = [
        d for d in recent_devs
        if d.get("online") or (d.get("last_seen") or 0) >= win_start - 3600 or (d.get("last_seen") or 0) == 0
    ]
    if not active_devs:
        active_devs = recent_devs[:6]
    else:
        active_devs = active_devs[:10]

    # Build unique (site_id, device) pairs covering EVERY site each MAC visited
    query_pairs: List[Tuple[str, Dict[str, Any]]] = []
    seen_pairs = set()
    for d in active_devs:
        sids = list(d.get("seen_site_ids") or [])
        if d.get("site_id") and d["site_id"] not in sids:
            sids.insert(0, d["site_id"])
        for sid in sids[:3]:
            key = (sid, d["mac_raw"])
            if sid and key not in seen_pairs:
                seen_pairs.add(key)
                query_pairs.append((sid, d))
    query_pairs = query_pairs[:12]

    def fetch_pair_apps(pair: Tuple[str, Dict[str, Any]]):
        sid, dev_obj = pair
        apps = _fetch_client_app_usage(session, api_host, sid, dev_obj["mac_raw"], win_start, win_end)
        return sid, dev_obj, apps

    app_totals: Dict[str, Dict[str, Any]] = {}  # lower_name -> {name, total_bytes, rx_bytes, tx_bytes, by_device}
    queried_devices_count = len({d["mac_raw"] for _, d in query_pairs})

    if query_pairs:
        with ThreadPoolExecutor(max_workers=min(6, len(query_pairs))) as pool:
            for sid, dev_obj, apps in pool.map(fetch_pair_apps, query_pairs):
                sname = site_name_map.get(sid) or dev_obj.get("site_name") or sid
                for a in apps:
                    aname = a["app"]
                    akey = aname.lower()
                    tb = float(a.get("total_bytes") or 0.0)
                    rxb = a.get("rx_bytes")
                    txb = a.get("tx_bytes")
                    if tb <= 0 and not ((rxb or 0) > 0 or (txb or 0) > 0):
                        continue
                    entry = app_totals.get(akey)
                    if entry is None:
                        entry = {
                            "name": aname,
                            "total_bytes": 0.0,
                            "rx_bytes": 0.0,
                            "tx_bytes": 0.0,
                            "has_rxtx": False,
                            "devices": {},
                        }
                        app_totals[akey] = entry
                    entry["total_bytes"] += tb
                    if rxb is not None or txb is not None:
                        entry["has_rxtx"] = True
                        entry["rx_bytes"] += float(rxb or 0.0)
                        entry["tx_bytes"] += float(txb or 0.0)
                    dkey = (dev_obj["mac_raw"], sid)
                    d_ent = entry["devices"].get(dkey)
                    if d_ent is None:
                        d_ent = {
                            "mac": dev_obj["mac"],
                            "label": _device_short_label(dev_obj),
                            "site_name": sname,
                            "site_id": sid,
                            "total_bytes": 0.0,
                            "rx_bytes": 0.0,
                            "tx_bytes": 0.0,
                            "has_rxtx": False,
                        }
                        entry["devices"][dkey] = d_ent
                    d_ent["total_bytes"] += tb
                    if rxb is not None or txb is not None:
                        d_ent["has_rxtx"] = True
                        d_ent["rx_bytes"] += float(rxb or 0.0)
                        d_ent["tx_bytes"] += float(txb or 0.0)

    ranked_apps = [x for x in sorted(app_totals.values(), key=lambda x: -x["total_bytes"]) if x["total_bytes"] > 0]
    total_classified_bytes = sum(x["total_bytes"] for x in ranked_apps)

    # Build clickable Mist Insights links for the user's devices
    links: List[Dict[str, str]] = []
    for d in active_devs[:4]:
        if d.get("site_id"):
            kind = "wired" if d.get("sources") == ["Wired"] else "client"
            links.append(_link_client(org_id, ui_host, d["site_id"], d["mac"], f"{d.get('hostname') or d['mac']} Insights", kind=kind))

    # Fetch historical client rx_bytes/tx_bytes/bytes across ALL queried (site, device) pairs
    # so disconnected clients still show their full accumulated total since midnight!
    total_client_bytes = 0.0
    total_client_rx = 0.0
    total_client_tx = 0.0
    any_client_rxtx = False
    per_device_totals: List[Dict[str, Any]] = []

    if (not ranked_apps or not requested_app) and query_pairs:
        def fetch_pair_bytes(pair: Tuple[str, Dict[str, Any]]):
            sid, dev_obj = pair
            is_wired_only = (dev_obj.get("sources") == ["Wired"])
            tb, rxb, txb, has_rt = _fetch_client_total_bytes(
                session, api_host, sid, dev_obj["mac_raw"], win_start, win_end, is_wired_only=is_wired_only
            )
            return sid, dev_obj, tb, rxb, txb, has_rt

        with ThreadPoolExecutor(max_workers=min(6, len(query_pairs))) as pool:
            for sid, dev_obj, tb, rxb, txb, has_rt in pool.map(fetch_pair_bytes, query_pairs):
                if tb > 0:
                    total_client_bytes += tb
                    if has_rt:
                        any_client_rxtx = True
                        total_client_rx += rxb
                        total_client_tx += txb
                    per_device_totals.append({
                        "mac": dev_obj["mac"],
                        "label": _device_short_label(dev_obj),
                        "online": bool(dev_obj.get("online")),
                        "site_name": site_name_map.get(sid) or dev_obj.get("site_name") or sid,
                        "total_bytes": tb,
                        "rx_bytes": rxb,
                        "tx_bytes": txb,
                        "has_rxtx": has_rt,
                    })
        per_device_totals.sort(key=lambda r: -r["total_bytes"])

    # Case 1: Specific application requested (e.g. "how much instagram traffic has nick.bull generated today")
    if requested_app:
        def app_matches(name_low: str) -> bool:
            norm_n = re.sub(r"[^a-z0-9]+", " ", name_low).strip()
            for tok in app_tokens:
                norm_t = re.sub(r"[^a-z0-9]+", " ", tok.lower()).strip()
                if norm_t and (norm_t in norm_n or norm_t.replace(" ", "") in norm_n.replace(" ", "")):
                    return True
            return False

        matched_apps = [a for a in ranked_apps if app_matches(a["name"].lower())]
        if matched_apps:
            sum_bytes = sum(a["total_bytes"] for a in matched_apps)
            sum_rx = sum(a["rx_bytes"] for a in matched_apps if a["has_rxtx"])
            sum_tx = sum(a["tx_bytes"] for a in matched_apps if a["has_rxtx"])
            has_rxtx = any(a["has_rxtx"] for a in matched_apps)
            pct_share = (sum_bytes / total_classified_bytes * 100.0) if total_classified_bytes > 0 else 0.0

            # Merge per-device hits across matched app variants
            dev_merged: Dict[str, Dict[str, Any]] = {}
            for a in matched_apps:
                for d_ent in a["devices"].values():
                    k = f"{d_ent['mac']}|{d_ent['site_name']}"
                    cur = dev_merged.get(k)
                    if cur is None:
                        dev_merged[k] = dict(d_ent)
                    else:
                        cur["total_bytes"] += d_ent["total_bytes"]
                        cur["rx_bytes"] += d_ent["rx_bytes"]
                        cur["tx_bytes"] += d_ent["tx_bytes"]
                        cur["has_rxtx"] = cur["has_rxtx"] or d_ent["has_rxtx"]
            dev_rows = sorted(dev_merged.values(), key=lambda x: -x["total_bytes"])
            per_dev_lines = [
                (
                    f"- **`{r['mac']}`** ({r['label']}, **{r['site_name']}**) — **{_fmt_bytes(r['total_bytes'])}**"
                    + (f" (↓ {_fmt_bytes(r['rx_bytes'])} / ↑ {_fmt_bytes(r['tx_bytes'])})" if r["has_rxtx"] else "")
                )
                for r in dev_rows[:8]
            ]
            other_top = [a for a in ranked_apps if a not in matched_apps][:4]
            other_note = (
                "\nOther top apps " + win_label + ": "
                + ", ".join(f"**{a['name']}** (`{_fmt_bytes(a['total_bytes'])}`)" for a in other_top)
                + "."
                if other_top else ""
            )
            rxtx_txt = f" (Download `{_fmt_bytes(sum_rx)}`, Upload `{_fmt_bytes(sum_tx)}`)" if has_rxtx else ""
            unique_dev_cnt = len({r["mac"] for r in dev_rows})
            reply = (
                f"**{display_user}** generated **{_fmt_bytes(sum_bytes)}** of **{requested_app}** traffic **{win_label}**{rxtx_txt} "
                f"across **{unique_dev_cnt}** device(s) ({pct_share:.1f}% of `{_fmt_bytes(total_classified_bytes)}` classified app traffic):\n"
                + "\n".join(per_dev_lines)
                + other_note
            )
            return {
                "reply": reply,
                "highlights": [
                    {"label": f"{requested_app} Traffic", "value": _fmt_bytes(sum_bytes)},
                    {"label": "Share of Apps", "value": f"{pct_share:.1f}%"},
                    {"label": "Devices Checked", "value": str(queried_devices_count)},
                    {"label": "Window", "value": win_label},
                ],
                "links": links,
                "context": {"last_client_query": target, "last_client_mode": mode},
            }

        # Specific app had 0 bytes recorded — show what apps WERE detected for this user!
        if ranked_apps:
            top_lines = [
                f"- **{a['name']}** — **{_fmt_bytes(a['total_bytes'])}**"
                + (f" (↓ {_fmt_bytes(a['rx_bytes'])} / ↑ {_fmt_bytes(a['tx_bytes'])})" if a["has_rxtx"] else "")
                for a in ranked_apps[:6]
            ]
            return {
                "reply": (
                    f"Mist Client Insights recorded **0 B** of **{requested_app}** traffic for **{display_user}** **{win_label}** "
                    f"(checked **{queried_devices_count}** device MAC(s)). Top apps observed instead:\n"
                    + "\n".join(top_lines)
                ),
                "highlights": [
                    {"label": f"{requested_app} Traffic", "value": "0 B"},
                    {"label": "Total App Traffic", "value": _fmt_bytes(total_classified_bytes)},
                    {"label": "Devices Checked", "value": str(queried_devices_count)},
                ],
                "links": links,
                "context": {"last_client_query": target, "last_client_mode": mode},
            }

        tot_rxtx = f" (↓ `{_fmt_bytes(total_client_rx)}` / ↑ `{_fmt_bytes(total_client_tx)}`)" if any_client_rxtx else ""
        tot_note = (
            f" Total historical client traffic recorded {win_label}: **{_fmt_bytes(total_client_bytes)}**{tot_rxtx}."
            if total_client_bytes > 0
            else ""
        )
        macs_preview = ", ".join(f"`{d['mac']}`" for d in active_devs[:4])
        return {
            "reply": (
                f"Mist Client Insights returned no per-application breakdown for **{display_user}** **{win_label}** "
                f"across **{queried_devices_count}** device MAC(s) ({macs_preview}).{tot_note} "
                f"Open Client Insights directly below to verify app classification in Mist."
            ),
            "highlights": [
                {"label": f"{requested_app} Traffic", "value": "No app stats"},
                {"label": "Total Traffic", "value": _fmt_bytes(total_client_bytes) if total_client_bytes > 0 else "--"},
                {"label": "Devices Checked", "value": str(queried_devices_count)},
            ],
            "links": links,
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    # Case 2: General traffic / application usage for user (works for BOTH online & disconnected clients!)
    effective_total = max(total_client_bytes, total_classified_bytes)
    since_note = f" (since `{_fmt_local_time(win_start, tzinfo)}`)" if win_label in ("today", "this morning") else ""
    online_cnt = sum(1 for d in active_devs if d.get("online"))
    offline_cnt = len(active_devs) - online_cnt
    conn_state_note = (
        "currently offline"
        if online_cnt == 0
        else (f"{online_cnt} online" if offline_cnt == 0 else f"{online_cnt} online, {offline_cnt} offline")
    )

    if effective_total > 0:
        sections: List[str] = []
        rxtx_clause = (
            f" (Download `{_fmt_bytes(total_client_rx)}`, Upload `{_fmt_bytes(total_client_tx)}`)"
            if any_client_rxtx and total_client_bytes >= total_classified_bytes
            else ""
        )
        header = (
            f"**{display_user}** used **{_fmt_bytes(effective_total)}** of traffic **{win_label}**{since_note}{rxtx_clause} "
            f"across **{queried_devices_count}** device(s) ({conn_state_note})."
        )
        sections.append(header)

        if per_device_totals:
            dev_lines = [
                (
                    f"- **`{r['mac']}`** ({r['label']} · {'Online' if r['online'] else 'Offline'} · **{r['site_name']}**) — "
                    f"**{_fmt_bytes(r['total_bytes'])}**"
                    + (f" (↓ {_fmt_bytes(r['rx_bytes'])} / ↑ {_fmt_bytes(r['tx_bytes'])})" if r["has_rxtx"] else "")
                )
                for r in per_device_totals[:8]
            ]
            sections.append("Traffic by device:\n" + "\n".join(dev_lines))

        if ranked_apps:
            app_lines = [
                f"- **#{i+1} {a['name']}** — **{_fmt_bytes(a['total_bytes'])}**"
                + (f" ({a['total_bytes'] / total_classified_bytes * 100:.1f}%)" if total_classified_bytes > 0 else "")
                + (f" · ↓ {_fmt_bytes(a['rx_bytes'])} / ↑ {_fmt_bytes(a['tx_bytes'])}" if a["has_rxtx"] else "")
                for i, a in enumerate(ranked_apps[:8])
            ]
            sections.append(f"Top classified apps (`{_fmt_bytes(total_classified_bytes)}`):\n" + "\n".join(app_lines))

        hl = [
            {"label": f"Total Traffic ({win_label})", "value": _fmt_bytes(effective_total)},
        ]
        if any_client_rxtx and total_client_bytes > 0:
            hl.append({"label": "Download / Upload", "value": f"{_fmt_bytes(total_client_rx)} / {_fmt_bytes(total_client_tx)}"})
        if ranked_apps:
            hl.append({"label": "Top App", "value": f"{ranked_apps[0]['name']} ({_fmt_bytes(ranked_apps[0]['total_bytes'])})"})
        hl.append({"label": "Devices Checked", "value": f"{queried_devices_count} ({conn_state_note})"})

        return {
            "reply": "\n".join(sections),
            "highlights": hl[:4],
            "links": links,
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    return {
        "reply": (
            f"Mist Client Insights returned no traffic or application telemetry for **{display_user}** **{win_label}**{since_note} "
            f"(checked **{queried_devices_count}** device MAC(s), {conn_state_note})."
        ),
        "highlights": [{"label": "Devices Checked", "value": str(queried_devices_count)}],
        "links": links,
        "context": {"last_client_query": target, "last_client_mode": mode},
    }


def _answer_client_question(
    message: str,
    target: str,
    mode: str,
    session: requests.Session,
    api_host: str,
    ui_host: str,
    org_id: str,
    snapshot: Dict[str, Any],
    tzinfo,
    now_ts: int,
) -> Dict[str, Any]:
    low = message.lower()
    ssid_filter = _detect_ssid_filter(message)
    mist_dur, win_start, win_end, win_label = _detect_time_window(message, now_ts, tzinfo)
    ask_first = any(k in low for k in ("first", "earliest", "start", "initially", "arrive", "arrived", "got in"))
    ask_nac = any(k in low for k in ("nac", "reject", "denied", "blocked", "radius", "server reject"))
    ask_apps, requested_app, app_tokens = _detect_app_query(message)
    ask_devices = any(
        k in low
        for k in (
            "devices", "device ", "mac address", "mac addresses", "all mac", "macs",
            "associated with", "connected with", "what has ", "which device", "what device",
            "show all ", "list all ",
        )
    )

    site_name_map = {str(s["id"]): str(s.get("name") or s["id"]) for s in (snapshot.get("sites") or []) if s.get("id")}

    # 1. Per-user / per-client application traffic (Mist Client Insights / Service Levels)
    if ask_apps and not ask_nac:
        return _answer_user_app_traffic(
            message=message,
            target=target,
            mode=mode,
            requested_app=requested_app,
            app_tokens=app_tokens,
            session=session,
            api_host=api_host,
            ui_host=ui_host,
            org_id=org_id,
            site_name_map=site_name_map,
            tzinfo=tzinfo,
            now_ts=now_ts,
        )

    # 2. All devices / MAC addresses associated with a user (with exact times seen)
    if ask_devices and not ask_nac:
        return _answer_user_devices(
            message=message,
            target=target,
            mode=mode,
            session=session,
            api_host=api_host,
            ui_host=ui_host,
            org_id=org_id,
            site_name_map=site_name_map,
            tzinfo=tzinfo,
            now_ts=now_ts,
        )

    # 3. If specifically asking about NAC rejects for this user/MAC, check Mist NAC denies directly
    if ask_nac:
        nac_params: Dict[str, Any] = {"duration": "1d" if mist_dur in ("1h", "24h") else mist_dur, "limit": 50}
        if mode == "mac":
            nac_params["mac"] = normalize_mac(target)
        else:
            nac_params["text"] = target if "*" in target else f"*{target}*"
        try:
            nac_hits = _mist_search_get(
                session, api_host, f"/api/v1/orgs/{org_id}/nac_clients/search", nac_params, max_pages=1
            )
        except Exception:
            nac_hits = []

        if nac_hits:
            denied = [h for h in nac_hits if "den" in str(h.get("status") or "").lower() or "rej" in str(h.get("status") or "").lower()]
            rows = denied if denied else nac_hits
            top = rows[0]
            sid = str(top.get("site_id") or "")
            sname = site_name_map.get(sid) or sid or "Unknown Site"
            cmac = format_mac(top.get("mac"))
            uname = str(top.get("username") or top.get("last_username") or top.get("idp_user") or target)
            reason = str(top.get("last_status_reason") or top.get("reason") or top.get("status") or "NAC event")
            ts = top.get("timestamp") or top.get("last_seen")
            links = []
            if cmac and sid:
                links.append(_link_client(org_id, ui_host, sid, cmac, f"{uname} (NAC Insights)", kind="nac"))
            if sid:
                links.append(_link_site(org_id, ui_host, sid, sname))
            return {
                "reply": (
                    f"Found **{len(rows)}** Mist NAC record(s) for **{uname}** in {win_label} "
                    f"({len(denied)} denied). Latest: **{reason}** at **{_fmt_local_time(ts, tzinfo, include_date=True)}** "
                    f"in **{sname}** (MAC `{cmac or '--'}`)."
                ),
                "highlights": [
                    {"label": "User", "value": uname},
                    {"label": "Denied Events", "value": str(len(denied))},
                    {"label": "Site", "value": sname},
                    {"label": "Latest", "value": _fmt_local_time(ts, tzinfo, include_date=True)},
                ],
                "links": links,
                "context": {"last_client_query": target, "last_client_mode": mode},
            }

    # Search Wi-Fi clients across Mist (using 7d if user asked about yesterday/week, else 24h; fallback to 7d if empty)
    search_dur = "7d" if mist_dur == "7d" else ("30d" if mist_dur == "30d" else "24h")
    res = search_wifi_clients(
        session=session,
        api_host=api_host,
        org_id=org_id,
        query=target,
        mode=mode,
        duration=search_dur,
        site_name_map=site_name_map,
    )
    clients = res.get("clients") or []

    # If nothing found in 24h, broaden automatically to 7d so we can tell them when they were last seen
    broadened = False
    if not clients and search_dur == "24h":
        res = search_wifi_clients(
            session=session,
            api_host=api_host,
            org_id=org_id,
            query=target,
            mode=mode,
            duration="7d",
            site_name_map=site_name_map,
        )
        clients = res.get("clients") or []
        broadened = bool(clients)

    # Also try username prefix match if user typed "nick.bull" and Mist stored "nick.bull@..." or vice versa
    if not clients and mode in ("username", "auto") and "@" not in target:
        res_text = search_wifi_clients(
            session=session,
            api_host=api_host,
            org_id=org_id,
            query=target,
            mode="auto",
            duration="7d",
            site_name_map=site_name_map,
        )
        clients = res_text.get("clients") or []
        broadened = bool(clients)

    # Fallback: check wired clients if no wireless client matched
    if not clients:
        wired_params: Dict[str, Any] = {"duration": "7d", "limit": 20}
        if mode == "mac":
            wired_params["mac"] = normalize_mac(target)
        elif mode == "ip":
            wired_params["ip"] = target
        else:
            wired_params["text"] = target
        try:
            wired_hits = _mist_search_get(
                session, api_host, f"/api/v1/orgs/{org_id}/wired_clients/search", wired_params, max_pages=1
            )
        except Exception:
            wired_hits = []
        if wired_hits:
            w = wired_hits[0]
            sid = str(w.get("site_id") or "")
            sname = site_name_map.get(sid) or sid or "Unknown Site"
            cmac = format_mac(w.get("mac"))
            w_user = str(w.get("username") or "")
            w_host = str(w.get("hostname") or cmac or target)
            w_ip = str(w.get("ip") or "--")
            w_port = str(w.get("port_id") or "--")
            w_ts = w.get("timestamp")
            links = []
            if cmac and sid:
                links.append(_link_client(org_id, ui_host, sid, cmac, f"{w_host} (Wired Client)", kind="wired"))
            if sid:
                links.append(_link_site(org_id, ui_host, sid, sname))
            return {
                "reply": (
                    f"No wireless client matched **`{target}`**, but I found a **wired client** in Mist: "
                    f"**{w_host}**{f' (user `{w_user}`)' if w_user else ''} in **{sname}** on port `{w_port}` "
                    f"(IP `{w_ip}`, VLAN `{w.get('vlan', '--')}`, last seen **{_fmt_local_time(w_ts, tzinfo, include_date=True)}**)."
                ),
                "highlights": [
                    {"label": "Wired Host", "value": w_host},
                    {"label": "Site", "value": sname},
                    {"label": "Port / VLAN", "value": f"{w_port} · VLAN {w.get('vlan', '--')}"},
                    {"label": "IP", "value": w_ip},
                ],
                "links": links,
                "context": {"last_client_query": target, "last_client_mode": mode},
            }

        return {
            "reply": (
                f"I searched Mist across wireless and wired clients for **`{target}`** (up to the last 7 days) "
                f"and didn't find any matching connections. Double-check the spelling or try their full email/UP number or MAC address."
            ),
            "highlights": [],
            "links": [],
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    # Fetch detailed events & sessions for up to 3 matching devices in parallel
    top_clients = clients[:3]
    details: List[Dict[str, Any]] = []

    def fetch_detail(c_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            return get_wifi_client_detail(
                session=session,
                api_host=api_host,
                org_id=org_id,
                mac=c_item["mac"],
                site_id=c_item.get("site_id") or "",
                duration="7d" if (broadened or mist_dur == "7d") else ("30d" if mist_dur == "30d" else "24h"),
                site_name_map=site_name_map,
            )
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(top_clients)) as pool:
        for d in pool.map(fetch_detail, top_clients):
            if d:
                details.append(d)

    # Collect candidate connection timestamps across events + sessions
    def ssid_matches(val: str) -> bool:
        if not ssid_filter:
            return True
        if not val:
            return False
        norm_v = " ".join(val.lower().replace("-", " ").replace("_", " ").split())
        norm_f = " ".join(ssid_filter.lower().replace("-", " ").replace("_", " ").split())
        return norm_f in norm_v or norm_v in norm_f

    in_window_hits: List[Dict[str, Any]] = []
    any_ssid_hits: List[Dict[str, Any]] = []

    for det in details:
        prof = det.get("profile") or {}
        dev_label = prof.get("hostname") or prof.get("model") or prof.get("family") or prof.get("mac") or "Device"
        prof_ssid = str(prof.get("ssid") or "")
        prof_mac = str(prof.get("mac") or "")
        prof_user = str(prof.get("username") or "")

        for ev in det.get("events") or []:
            ts = ev.get("timestamp") or 0
            if ts <= 0:
                continue
            ev_ssid = str(ev.get("ssid") or prof_ssid)
            if not ssid_matches(ev_ssid):
                continue
            cat = ev.get("category") or ""
            ev_type = str(ev.get("type") or "").lower()
            is_conn = cat == "connect" or any(k in ev_type for k in ("assoc", "auth", "join", "connect", "dhcp", "roam", "session"))
            if not is_conn:
                continue
            rec = {
                "ts": int(ts),
                "device": dev_label,
                "mac": prof_mac,
                "username": prof_user,
                "ssid": ev_ssid or ssid_filter or "Wi-Fi",
                "site_id": str(ev.get("site_id") or prof.get("site_id") or ""),
                "site_name": str(ev.get("site_name") or prof.get("site_name") or "Unknown Site"),
                "ap_name": str(ev.get("ap_name") or prof.get("ap_name") or "Unknown AP"),
                "ap_mac": str(ev.get("ap_mac") or prof.get("ap_mac") or ""),
                "rssi": ev.get("rssi") if ev.get("rssi") is not None else prof.get("rssi"),
                "source": ev.get("type") or "event",
            }
            any_ssid_hits.append(rec)
            if win_start <= ts <= win_end:
                in_window_hits.append(rec)

        for sess in det.get("sessions") or []:
            s_ts = sess.get("timestamp") or 0
            if s_ts <= 0:
                continue
            s_dur = sess.get("duration") or 0
            start_ts = int(s_ts - s_dur) if (isinstance(s_dur, (int, float)) and s_dur > 0) else int(s_ts)
            s_ssid = str(sess.get("ssid") or prof_ssid)
            if not ssid_matches(s_ssid):
                continue
            rec = {
                "ts": start_ts,
                "device": dev_label,
                "mac": prof_mac,
                "username": str(sess.get("username") or prof_user),
                "ssid": s_ssid or ssid_filter or "Wi-Fi",
                "site_id": str(sess.get("site_id") or prof.get("site_id") or ""),
                "site_name": str(sess.get("site_name") or prof.get("site_name") or "Unknown Site"),
                "ap_name": str(sess.get("ap_name") or prof.get("ap_name") or "Unknown AP"),
                "ap_mac": str(sess.get("ap_mac") or prof.get("ap_mac") or ""),
                "rssi": prof.get("rssi"),
                "source": "session_start",
            }
            any_ssid_hits.append(rec)
            if win_start <= start_ts <= win_end:
                in_window_hits.append(rec)

        # Fallback: if online right now with uptime, compute session start = now - uptime
        if prof.get("online") and isinstance(prof.get("uptime"), (int, float)) and prof["uptime"] > 0:
            if ssid_matches(prof_ssid):
                start_ts = int(now_ts - prof["uptime"])
                rec = {
                    "ts": start_ts,
                    "device": dev_label,
                    "mac": prof_mac,
                    "username": prof_user,
                    "ssid": prof_ssid or ssid_filter or "Wi-Fi",
                    "site_id": str(prof.get("site_id") or ""),
                    "site_name": str(prof.get("site_name") or "Unknown Site"),
                    "ap_name": str(prof.get("ap_name") or "Unknown AP"),
                    "ap_mac": str(prof.get("ap_mac") or ""),
                    "rssi": prof.get("rssi"),
                    "source": "live_uptime",
                }
                any_ssid_hits.append(rec)
                if win_start <= start_ts <= win_end:
                    in_window_hits.append(rec)

    primary_prof = (details[0].get("profile") if details else None) or clients[0]
    display_user = primary_prof.get("username") or primary_prof.get("hostname") or target
    online_now = any(bool((d.get("profile") or {}).get("online")) for d in details) or bool(primary_prof.get("online"))
    live_prof = next((d["profile"] for d in details if (d.get("profile") or {}).get("online")), primary_prof)

    links: List[Dict[str, str]] = []
    if live_prof.get("mac") and live_prof.get("site_id"):
        links.append(_link_client(org_id, ui_host, live_prof["site_id"], live_prof["mac"], f"{display_user} in Mist", kind="client"))
    if live_prof.get("ap_mac") and live_prof.get("site_id"):
        links.append(_link_ap(org_id, ui_host, live_prof["site_id"], "", live_prof["ap_mac"], live_prof.get("ap_name") or "AP"))
    if live_prof.get("site_id"):
        links.append(_link_site(org_id, ui_host, live_prof["site_id"], live_prof.get("site_name") or "Site"))

    if ask_first:
        in_window_hits.sort(key=lambda r: r["ts"])
        any_ssid_hits.sort(key=lambda r: r["ts"])
        if in_window_hits:
            earliest = in_window_hits[0]
            t_str = _fmt_local_time(earliest["ts"], tzinfo, include_date=True)
            rel = _fmt_rel_ago(earliest["ts"], now_ts)
            now_clause = (
                f"Currently **online** on **{live_prof.get('ap_name', '--')}** ({live_prof.get('site_name', '--')}, "
                f"RSSI `{live_prof.get('rssi', '--')} dBm`, IP `{live_prof.get('ip') or '--'}`)."
                if online_now
                else f"Currently **offline** (last seen {_fmt_local_time(live_prof.get('last_seen'), tzinfo, include_date=True)})."
            )
            reply = (
                f"**{display_user}** first connected to **{earliest['ssid']}** {win_label} at "
                f"**{t_str}** ({rel}) on **{earliest['ap_name']}** in **{earliest['site_name']}** "
                f"(device: `{earliest['device']}`, MAC `{earliest['mac']}`).\n{now_clause}"
            )
            highlights = [
                {"label": "First Connected", "value": _fmt_local_time(earliest["ts"], tzinfo)},
                {"label": "SSID", "value": earliest["ssid"]},
                {"label": "First AP & Site", "value": f"{earliest['ap_name']} ({earliest['site_name']})"},
                {"label": "Live Status", "value": "Online" if online_now else "Offline"},
            ]
        elif any_ssid_hits:
            latest = max(any_ssid_hits, key=lambda r: r["ts"])
            reply = (
                f"I didn't see a connection for **{display_user}**"
                f"{f' on **{ssid_filter}**' if ssid_filter else ''} during {win_label}. "
                f"Their most recent matching connection was **{_fmt_local_time(latest['ts'], tzinfo, include_date=True)}** "
                f"on **{latest['ap_name']}** in **{latest['site_name']}**."
            )
            highlights = [
                {"label": "Window", "value": f"No join in {win_label}"},
                {"label": "Last Seen", "value": _fmt_local_time(latest["ts"], tzinfo, include_date=True)},
                {"label": "Site", "value": latest["site_name"]},
            ]
        else:
            last_seen = primary_prof.get("last_seen")
            reply = (
                f"Found **{display_user}** (`{primary_prof.get('mac', '--')}`), but Mist returned no "
                f"{f'**{ssid_filter}** ' if ssid_filter else ''}join events for {win_label}. "
                f"Last observed on **{primary_prof.get('ssid') or 'Wi-Fi'}** at **{primary_prof.get('site_name', '--')}** "
                f"({_fmt_local_time(last_seen, tzinfo, include_date=True)})."
            )
            highlights = [
                {"label": "User / Host", "value": display_user},
                {"label": "Last SSID", "value": primary_prof.get("ssid") or "--"},
                {"label": "Last Site", "value": primary_prof.get("site_name") or "--"},
            ]
        return {
            "reply": reply,
            "highlights": highlights,
            "links": links,
            "context": {"last_client_query": target, "last_client_mode": mode},
        }

    # General client status / location / signal answer
    rssi_val = live_prof.get("rssi")
    rssi_txt = f"{rssi_val} dBm ({(live_prof.get('signal_quality') or {}).get('label', '')})" if isinstance(rssi_val, (int, float)) else "--"
    first_today_note = ""
    if in_window_hits:
        in_window_hits.sort(key=lambda r: r["ts"])
        first_today_note = f" First seen {win_label} at **{_fmt_local_time(in_window_hits[0]['ts'], tzinfo)}**."

    status_word = "currently **online**" if online_now else f"currently **offline** (last seen **{_fmt_local_time(live_prof.get('last_seen'), tzinfo, include_date=True)}**)"
    reply = (
        f"**{display_user}** (`{live_prof.get('hostname') or live_prof.get('mac')}`) is {status_word} "
        f"on **{live_prof.get('ssid') or 'Wi-Fi'}** at **{live_prof.get('site_name', '--')}** "
        f"via AP **{live_prof.get('ap_name', '--')}** (IP `{live_prof.get('ip') or '--'}`, "
        f"Band `{live_prof.get('band') or '--'}`, Signal `{rssi_txt}`).{first_today_note}"
    )
    if len(clients) > 1:
        other_macs = ", ".join(f"`{c['mac']}` ({_device_short_label(c)})" for c in clients[:6])
        more_c = f" +{len(clients) - 6} more" if len(clients) > 6 else ""
        reply += f"\nAll **{len(clients)}** matched MAC(s): {other_macs}{more_c}."

    return {
        "reply": reply,
        "highlights": [
            {"label": "Status", "value": "Online" if online_now else "Offline"},
            {"label": "AP & Site", "value": f"{live_prof.get('ap_name', '--')} ({live_prof.get('site_name', '--')})"},
            {"label": "SSID / IP", "value": f"{live_prof.get('ssid') or '--'} · {live_prof.get('ip') or '--'}"},
            {"label": "Signal", "value": rssi_txt},
        ],
        "links": links,
        "context": {"last_client_query": target, "last_client_mode": mode},
    }


def _optional_llm_answer(message: str, snapshot: Dict[str, Any], history_msgs: List[Dict[str, str]]) -> Optional[str]:
    """Optional LLM fallback if GEMINI_API_KEY or OPENAI_API_KEY is configured in .env (0 extra pip deps)."""
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not gemini_key and not openai_key:
        return None

    sum_d = snapshot.get("summary") or {}
    context_summary = (
        f"Org: {(snapshot.get('org') or {}).get('name', 'Mist Org')}. "
        f"Wireless users: {sum_d.get('total_wireless_users', 0)} "
        f"(eduroam: {sum_d.get('eduroam_users', 0)}, UoP Visitor: {sum_d.get('uop_visitor_users', 0)}, "
        f"UoP Connect: {sum_d.get('uop_connect_users', 0)}). "
        f"APs: {sum_d.get('aps_online', 0)} online / {sum_d.get('aps_offline', 0)} offline. "
        f"Switches: {sum_d.get('switches_online', 0)} online / {sum_d.get('switches_offline', 0)} offline. "
        f"Down VC members/PFEs: {sum_d.get('vc_member_issues_count', 0)}. "
        f"Recent filtered alarms: {len(snapshot.get('alarms') or [])}."
    )
    sys_prompt = (
        "You are a concise, accurate Juniper Mist network operations assistant embedded in a read-only dashboard. "
        "Answer using ONLY the provided live Mist telemetry; never invent device names, times, or metrics. "
        f"Live snapshot summary: {context_summary}"
    )

    try:
        if gemini_key:
            model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                params={"key": gemini_key},
                json={
                    "system_instruction": {"parts": [{"text": sys_prompt}]},
                    "contents": [{"role": "user", "parts": [{"text": message}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 400},
                },
                timeout=15,
            )
            if resp.ok:
                cands = resp.json().get("candidates") or []
                if cands:
                    parts = (cands[0].get("content") or {}).get("parts") or []
                    txt = "".join(str(p.get("text") or "") for p in parts).strip()
                    if txt:
                        return txt
        elif openai_key:
            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {openai_key}"},
                json={
                    "model": model,
                    "temperature": 0.2,
                    "max_tokens": 400,
                    "messages": [
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": message},
                    ],
                },
                timeout=15,
            )
            if resp.ok:
                choices = resp.json().get("choices") or []
                if choices:
                    txt = str((choices[0].get("message") or {}).get("content") or "").strip()
                    if txt:
                        return txt
    except Exception:
        return None
    return None


def answer_mist_chat(
    message: str,
    snapshot: Dict[str, Any],
    session: requests.Session,
    api_host: str,
    ui_host: str,
    org_id: str,
    history_db_path,
    context: Optional[Dict[str, Any]] = None,
    tz_name: Optional[str] = None,
    tz_offset_minutes: Optional[int] = None,
    nac_cached_data: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Natural-language Mist assistant combining live snapshot telemetry, SQLite history, and live Mist API lookups."""
    text = (message or "").strip()
    if not text:
        return {
            "reply": "Ask me anything about your Mist org — e.g. *\"What time did nick.bull first connect to eduroam this morning?\"* or *\"Which switches are down?\"*",
            "highlights": [],
            "links": [],
            "context": context or {},
        }

    low = text.lower()
    now_epoch = int(now_ts if now_ts is not None else time.time())
    tzinfo = _resolve_tz(tz_name, tz_offset_minutes)
    ctx = dict(context or {})
    sites = snapshot.get("sites") or []
    summary = snapshot.get("summary") or {}
    mentioned_site = _find_mentioned_site(text, sites)

    # 1. Help / capabilities
    if re.search(r"^(?:help|\?|what can you do|commands|examples)\b", low):
        return {
            "reply": (
                "I'm connected directly to your **Mist organization** (read-only). You can ask me things like:\n"
                "- **User Devices & MACs**: *\"Show the devices associated with nick.bull\"*, *\"What devices has nick.bull connected with today and the time seen?\"*\n"
                "- **App Traffic (Service Levels / Insights)**: *\"How much Instagram traffic has nick.bull generated today?\"*, *\"What apps has nick.bull used today?\"*, *\"Top apps at Library today\"*\n"
                "- **Client Lookups & Join Times**: *\"What time did nick.bull first connect to eduroam this morning?\"*, *\"Where is up123456 connected?\"*, *\"Who has 10.20.1.55?\"*\n"
                "- **Outages & VC Health**: *\"Which switches or VC members are down?\"*, *\"Any PFE faults?\"*, *\"What's the hottest VC?\"*\n"
                "- **Wi-Fi, Peaks, Alarms & NAC**: *\"How many users are on eduroam?\"*, *\"What was today's Wi-Fi peak?\"*, *\"Show critical alarms\"*, *\"Was nick.bull rejected by NAC?\"*"
            ),
            "highlights": [],
            "links": [],
            "context": ctx,
        }

    # 2. Check for explicit client/user lookup FIRST when a specific user/MAC/IP is detected
    #    (or follow-up pronoun with client intent)
    client_intent_words = (
        "connect", "connected", "join", "joined", "first", "last seen", "where is", "who is",
        "who has", "who's using", "lookup", "find", "locate", "signal", "rssi", "wifi", "wi-fi",
        "eduroam", "roam", "session", "nac", "reject", "denied", "online", "offline", "ip", "mac",
        "macs", "device", "devices", "associated", "traffic", "usage", "bandwidth", "generated",
        "app", "apps", "application", "applications", "instagram", "youtube", "tiktok", "teams",
        "zoom", "netflix", "spotify", "whatsapp", "facebook",
    )
    target, mode = _extract_client_target(text, ctx, sites)
    mentioned_dev = _find_mentioned_device(text, snapshot)

    if target and not mentioned_dev and (
        mode in ("mac", "ip", "username")
        or any(w in low for w in client_intent_words)
    ):
        return _answer_client_question(
            message=text,
            target=target,
            mode=mode,
            session=session,
            api_host=api_host,
            ui_host=ui_host,
            org_id=org_id,
            snapshot=snapshot,
            tzinfo=tzinfo,
            now_ts=now_epoch,
        )

    # 3. Down VC Members / Offline Linecards / PFE Faults (and combined "switches or VC members")
    if any(k in low for k in ("pfe", "linecard", "line card", "vc member", "fpc", "chassis member")):
        also_switches = any(k in low for k in ("switch", "switches"))
        issues = list(snapshot.get("vc_member_issues") or [])
        off_sw = list(snapshot.get("offline_switches") or []) if also_switches else []
        if mentioned_site:
            sname_low = mentioned_site["name"].lower()
            issues = [i for i in issues if (i.get("site_name") or "").lower() == sname_low]
            off_sw = [d for d in off_sw if (d.get("site_name") or "").lower() == sname_low]
        scope = f" in **{mentioned_site['name']}**" if mentioned_site else ""
        if not issues and not off_sw:
            scanned = bool((snapshot.get("vc_member_issues_meta") or {}).get("scanned"))
            note = "" if scanned else " (Switch `module_stat` hasn't been scanned per-site yet — run a scan in **Devices Down** for full FPC/PFE telemetry.)"
            subject_lbl = "offline switches, down Virtual Chassis members, or PFE faults" if also_switches else "down Virtual Chassis members, offline linecards, or PFE faults"
            return {
                "reply": f"No {subject_lbl} detected{scope}.{note}",
                "highlights": [
                    *([{"label": "Switches Down", "value": "0"}] if also_switches else []),
                    {"label": "VC Member / PFE Faults", "value": "0"},
                ],
                "links": [],
                "context": ctx,
                "action_tab": "tab-devices-down",
            }
        lines = []
        links = []
        for sw in off_sw[:4]:
            lines.append(
                f"- **[Switch Down] {sw.get('name')}** ({sw.get('site_name')}) — `{sw.get('model') or '--'}` · "
                f"last seen {_fmt_rel_ago(sw.get('last_seen'), now_epoch) or 'unknown'}"
            )
            links.append(_link_switch(org_id, ui_host, sw.get("site_id", ""), sw.get("id", ""), sw.get("mac", ""), sw.get("name", "Switch")))
        for it in issues[:6]:
            lines.append(
                f"- **[VC Member / PFE] {it.get('switch_name')}** ({it.get('site_name')}) — `{it.get('member_label')}`: "
                f"**{it.get('issue_type')}** (`{it.get('state')}`)"
            )
            links.append(_link_switch(org_id, ui_host, it.get("site_id", ""), it.get("device_id", ""), it.get("mac", ""), it.get("switch_name", "Switch")))
        header = (
            f"Found **{len(off_sw)}** offline switch(es) and **{len(issues)}** down VC member / PFE fault(s){scope}:"
            if also_switches
            else f"Found **{len(issues)}** down VC member / PFE fault(s){scope}:"
        )
        highlights = []
        if also_switches:
            highlights.append({"label": "Switches Down", "value": str(len(off_sw))})
        highlights.append({"label": "VC Member / PFEs", "value": str(len(issues))})
        return {
            "reply": header + "\n" + "\n".join(lines),
            "highlights": highlights,
            "links": links[:4],
            "context": ctx,
            "action_tab": "tab-devices-down",
        }

    # 4. Down Devices / Offline Switches / Offline APs
    if any(k in low for k in ("down", "offline", "disconnected", "outage")) and not any(k in low for k in ("alarm", "alert")):
        want_sw = any(k in low for k in ("switch", "switches", "vc"))
        want_ap = any(k in low for k in ("ap", "aps", "access point"))
        off_sw = list(snapshot.get("offline_switches") or [])
        off_ap = list(snapshot.get("offline_aps") or [])
        vc_issues = list(snapshot.get("vc_member_issues") or [])
        if mentioned_site:
            sname_low = mentioned_site["name"].lower()
            off_sw = [d for d in off_sw if (d.get("site_name") or "").lower() == sname_low]
            off_ap = [d for d in off_ap if (d.get("site_name") or "").lower() == sname_low]
            vc_issues = [d for d in vc_issues if (d.get("site_name") or "").lower() == sname_low]

        if want_sw and not want_ap:
            items = off_sw
            kind_lbl = "switches"
        elif want_ap and not want_sw:
            items = off_ap
            kind_lbl = "access points"
        else:
            items = off_sw + off_ap
            kind_lbl = "devices"

        scope = f" in **{mentioned_site['name']}**" if mentioned_site else ""
        if not items and (want_ap or not vc_issues):
            return {
                "reply": f"All {kind_lbl}{scope} are currently **online**! ({summary.get('switches_online', 0)} switches & {summary.get('aps_online', 0)} APs connected.)",
                "highlights": [
                    {"label": "Switches Down", "value": str(len(off_sw))},
                    {"label": "APs Down", "value": str(len(off_ap))},
                    {"label": "VC Member Faults", "value": str(len(vc_issues))},
                ],
                "links": [_link_site(org_id, ui_host, mentioned_site["id"], mentioned_site["name"])] if mentioned_site else [],
                "context": ctx,
            }

        lines = []
        links = []
        for d in items[:6]:
            dtype = d.get("device_type") or ("Switch" if d in off_sw else "AP")
            lines.append(f"- **[{dtype}] {d.get('name')}** ({d.get('site_name')}) — `{d.get('model') or '--'}` · last seen {_fmt_rel_ago(d.get('last_seen'), now_epoch) or 'unknown'}")
            if dtype == "Switch":
                links.append(_link_switch(org_id, ui_host, d.get("site_id", ""), d.get("id", ""), d.get("mac", ""), d.get("name", "Switch")))
            else:
                links.append(_link_ap(org_id, ui_host, d.get("site_id", ""), d.get("id", ""), d.get("mac", ""), d.get("name", "AP")))
        more = f"\n…and **{len(items) - 6}** more." if len(items) > 6 else ""
        vc_note = f"\nAlso active: **{len(vc_issues)}** down VC member / PFE fault(s)." if (vc_issues and not want_ap) else ""
        return {
            "reply": f"There are **{len(items)}** offline {kind_lbl}{scope}:\n" + "\n".join(lines) + more + vc_note,
            "highlights": [
                {"label": "Switches Down", "value": str(len(off_sw))},
                {"label": "APs Down", "value": str(len(off_ap))},
                {"label": "VC Member / PFEs", "value": str(len(vc_issues))},
            ],
            "links": links[:4],
            "context": ctx,
            "action_tab": "tab-devices-down",
        }

    # 5. Hottest VCs / Thermal Alarms / EX4000-4100
    if any(k in low for k in ("hottest", "hot", "temp", "temperature", "thermal", "overheat", "ex4000", "ex4100", "4000", "4100")):
        vc_meta = snapshot.get("vc_temps_meta") or {}
        if not vc_meta.get("scanned"):
            return {
                "reply": "Switch temperature telemetry hasn't been scanned yet. Open the **Hottest VCs** tab and click **Scan VC Temps** to inspect live FPC sensor temperatures.",
                "highlights": [{"label": "Threshold", "value": f"{vc_meta.get('threshold_c', 60)}°C"}],
                "links": [],
                "context": ctx,
                "action_tab": "tab-hottest-vcs",
            }
        want_4k = any(k in low for k in ("4000", "4100", "41000"))
        all_vc = list(snapshot.get("vc_temps") or [])
        pool_vc = [x for x in all_vc if bool(x.get("is_ex4000_4100")) == want_4k]
        if not want_4k and any(x.get("is_vc") for x in pool_vc):
            pool_vc = [x for x in pool_vc if x.get("is_vc")]
        if mentioned_site:
            pool_vc = [x for x in pool_vc if (x.get("site_name") or "").lower() == mentioned_site["name"].lower()]
        thresh = vc_meta.get("threshold_c", 60)
        label_grp = "EX4000 / EX4100 switches" if want_4k else "Virtual Chassis"
        if not pool_vc:
            return {
                "reply": f"No {label_grp} reported temperature sensors" + (f" in **{mentioned_site['name']}**" if mentioned_site else "") + ".",
                "highlights": [],
                "links": [],
                "context": ctx,
                "action_tab": "tab-hottest-vcs",
            }
        alarmed = [x for x in pool_vc if x.get("above_threshold")]
        top = pool_vc[:5]
        lines = [
            f"- **#{i+1} {x['name']}** ({x['site_name']}) — **{x['peak_temp_c']}°C** "
            f"({x.get('hottest_member', 'Chassis')} · {x.get('hottest_sensor', 'Sensor')})"
            f"{' · **ALARM**' if x.get('above_threshold') else ''}"
            for i, x in enumerate(top)
        ]
        links = [
            _link_switch(org_id, ui_host, x.get("site_id", ""), x.get("id", ""), x.get("vc_mac") or x.get("mac", ""), x["name"])
            for x in top[:4]
        ]
        return {
            "reply": (
                f"Hottest **{label_grp}** (threshold `{thresh}°C`, **{len(alarmed)}** above threshold):\n"
                + "\n".join(lines)
            ),
            "highlights": [
                {"label": "#1 Peak", "value": f"{top[0]['peak_temp_c']}°C ({top[0]['name']})"},
                {"label": f"Above {thresh}°C", "value": str(len(alarmed))},
                {"label": "Monitored", "value": str(len(pool_vc))},
            ],
            "links": links,
            "context": ctx,
            "action_tab": "tab-hottest-vcs",
        }

    # 6. Recent Alarms
    if any(k in low for k in ("alarm", "alarms", "alert", "alerts")):
        want_crit = "critical" in low or "crit" in low
        want_all = "all" in low or "info" in low
        pool_a = list(snapshot.get("alarms_all" if want_all else "alarms") or [])
        if want_crit:
            pool_a = [a for a in pool_a if str(a.get("severity") or "").lower() == "critical"]
        if mentioned_site:
            pool_a = [a for a in pool_a if (a.get("site_name") or "").lower() == mentioned_site["name"].lower()]
        scope = f" in **{mentioned_site['name']}**" if mentioned_site else ""
        if not pool_a:
            return {
                "reply": f"No matching {'critical ' if want_crit else ''}alarms found{scope} in the last 24 hours.",
                "highlights": [{"label": "Matching Alarms", "value": "0"}],
                "links": [_link_alerts(org_id, ui_host, mentioned_site["id"] if mentioned_site else "", "Open Mist Alerts")],
                "context": ctx,
                "action_tab": "tab-alarms",
            }
        lines = []
        links = []
        for a in pool_a[:6]:
            dev = f" · `{a['device_name']}`" if a.get("device_name") else ""
            lines.append(f"- **[{str(a.get('severity', '')).upper()}] {a.get('site_name')} — {a.get('type')}**{dev}: {a.get('text')}")
            if a.get("device_name") and a.get("device_type") == "switch":
                links.append(_link_switch(org_id, ui_host, a.get("site_id", ""), a.get("device_id", ""), a.get("device_mac", ""), a["device_name"]))
            elif a.get("device_name") and a.get("device_type") == "ap":
                links.append(_link_ap(org_id, ui_host, a.get("site_id", ""), a.get("device_id", ""), a.get("device_mac", ""), a["device_name"]))
        links.append(_link_alerts(org_id, ui_host, mentioned_site["id"] if mentioned_site else "", "Open Mist Alerts"))
        return {
            "reply": f"Found **{len(pool_a)}** {'critical ' if want_crit else ''}alarm(s){scope} (last 24h):\n" + "\n".join(lines),
            "highlights": [{"label": "Alarms Shown", "value": str(len(pool_a))}],
            "links": links[:4],
            "context": ctx,
            "action_tab": "tab-alarms",
        }

    # 7. Wi-Fi History & Concurrent Peaks (0 Mist API calls — local SQLite)
    if any(k in low for k in ("peak", "peaks", "history", "highest", "record", "max users", "maximum users")):
        rng = "all" if any(k in low for k in ("all time", "all-time", "ever")) else (
            "year" if "year" in low else (
                "month" if "month" in low else (
                    "week" if "week" in low else "day"
                )
            )
        )
        anchor = None
        if "yesterday" in low:
            rng = "day"
            anchor = (datetime.fromtimestamp(now_epoch, tz=tzinfo) - timedelta(days=1)).strftime("%Y-%m-%d")
        ssid_q = _detect_ssid_filter(text) or "all"
        try:
            hist = query_history(history_db_path, range_type=rng, anchor=anchor, ssid=ssid_q, now_ts=now_epoch)
            sample_count = int(hist.get("sample_count") or 0)
            sel_peak = (hist.get("peaks") or {}).get("selected") or {}
            peak_val = sel_peak.get("value") if sample_count > 0 else None
            peak_ts = sel_peak.get("ts")
            avg_val = hist.get("avg_selected") or 0
            label_p = hist.get("period_label") or rng
            ssid_lbl = hist.get("ssid_label") or (ssid_q if ssid_q != "all" else "Total Wi-Fi")
            if peak_val is None or peak_ts is None:
                return {
                    "reply": f"No historical samples recorded yet for **{label_p}**.",
                    "highlights": [],
                    "links": [],
                    "context": ctx,
                    "action_tab": "tab-history",
                }
            all_time = peak_val
            if rng != "all":
                all_hist = query_history(history_db_path, range_type="all", ssid=ssid_q, now_ts=now_epoch)
                all_sel = (all_hist.get("peaks") or {}).get("selected") or {}
                if all_sel.get("ts") is not None:
                    all_time = all_sel.get("value") or peak_val
            return {
                "reply": (
                    f"Peak concurrent **{ssid_lbl}** users for **{label_p}** "
                    f"was **{int(peak_val):,}** (recorded **{_fmt_local_time(peak_ts, tzinfo, include_date=True)}**). "
                    f"Period average: **{int(avg_val):,}**, all-time peak: **{int(all_time):,}** ({sample_count:,} sample{'s' if sample_count != 1 else ''})."
                ),
                "highlights": [
                    {"label": "Period Peak", "value": f"{int(peak_val):,}"},
                    {"label": "Peak Time", "value": _fmt_local_time(peak_ts, tzinfo, include_date=True)},
                    {"label": "All-Time Peak", "value": f"{int(all_time):,}"},
                ],
                "links": [],
                "context": ctx,
                "action_tab": "tab-history",
            }
        except Exception:
            pass

    # 8. APs < 1Gb Uplinks
    if any(k in low for k in ("< 1g", "<1g", "under 1g", "sub-1g", "sub 1g", "100 mbps", "100mbps", "slow ap", "uplink")):
        slow_meta = snapshot.get("slow_aps_meta") or {}
        if not slow_meta.get("scanned"):
            est = slow_meta.get("estimated_calls", 1)
            return {
                "reply": f"AP uplink speeds haven't been scanned yet (on-demand to save Mist API quota; ~{est} API calls). Open **APs < 1Gb** and click **Scan AP Uplinks**.",
                "highlights": [{"label": "Est. API Calls", "value": f"~{est}"}],
                "links": [],
                "context": ctx,
                "action_tab": "tab-ap-issues",
            }
        slow = list(snapshot.get("slow_aps") or [])
        if mentioned_site:
            slow = [a for a in slow if (a.get("site_name") or "").lower() == mentioned_site["name"].lower()]
        if not slow:
            return {
                "reply": "All scanned APs are negotiated at **1 Gbps or higher (Full Duplex)**!",
                "highlights": [{"label": "APs < 1Gb", "value": "0"}],
                "links": [],
                "context": ctx,
                "action_tab": "tab-ap-issues",
            }
        lines = [
            f"- **{a['name']}** ({a['site_name']}) — **{a.get('speed_label', a.get('speed'))}** {a.get('duplex', '')} via **{a.get('switch_name', '--')}** `{a.get('switch_port', '--')}`"
            for a in slow[:6]
        ]
        links = [_link_ap(org_id, ui_host, a.get("site_id", ""), a.get("id", ""), a.get("mac", ""), a["name"]) for a in slow[:4]]
        return {
            "reply": f"Found **{len(slow)}** AP(s) running below 1 Gbps:\n" + "\n".join(lines),
            "highlights": [{"label": "APs < 1Gb", "value": str(len(slow))}],
            "links": links,
            "context": ctx,
            "action_tab": "tab-ap-issues",
        }

    # 9. NAC Server Rejects summary
    if any(k in low for k in ("nac", "server reject", "rejected", "802.1x")):
        if nac_cached_data and isinstance(nac_cached_data.get("devices"), list):
            devs = list(nac_cached_data["devices"])
            if mentioned_site:
                devs = [d for d in devs if (d.get("site_name") or "").lower() == mentioned_site["name"].lower()]
            if not devs:
                return {
                    "reply": "No NAC Server Rejects found in the cached 24h scan.",
                    "highlights": [{"label": "NAC Rejects", "value": "0"}],
                    "links": [],
                    "context": ctx,
                    "action_tab": "tab-nac-rejects",
                }
            lines = [
                (
                    f"- **{d.get('hostname') or d.get('mac')}**"
                    + (f" (user `{d.get('username')}`)" if d.get("username") else "")
                    + f" — {d.get('site_name')} · **{d.get('switch_name')}** `{d.get('port_id')}` ({d.get('reject_type')})"
                )
                for d in devs[:6]
            ]
            links = [_link_client(org_id, ui_host, d.get("site_id", ""), d.get("mac", ""), d.get("username") or d.get("hostname") or d.get("mac", "Client"), kind="nac") for d in devs[:4]]
            return {
                "reply": f"Found **{len(devs)}** NAC Server Reject(s) in the last 24h:\n" + "\n".join(lines),
                "highlights": [{"label": "Devices Rejected", "value": str(len(devs))}],
                "links": links,
                "context": ctx,
                "action_tab": "tab-nac-rejects",
            }
        return {
            "reply": "NAC Server Rejects are pulled on-demand to conserve API quota. Open the **NAC Server Rejects** tab and click **Pull NAC Server Rejects**, or ask me about a specific user (e.g. *\"Was nick.bull rejected by NAC?\"*).",
            "highlights": [{"label": "Est. API Calls", "value": "~4–12"}],
            "links": [],
            "context": ctx,
            "action_tab": "tab-nac-rejects",
        }

    # 10. Specific known device status (VC / Switch / AP)
    if mentioned_dev:
        dkind, dobj = mentioned_dev
        if dkind == "vc":
            return {
                "reply": (
                    f"**{dobj['name']}** (`{dobj.get('model') or 'Switch'}`, {dobj.get('site_name')}) is **connected**. "
                    f"Peak temp: **{dobj.get('peak_temp_c')}°C** on `{dobj.get('hottest_member')}` ({dobj.get('hottest_sensor')}), "
                    f"avg **{dobj.get('avg_temp_c')}°C** (status: **{'ALARM' if dobj.get('above_threshold') else 'Normal'}**)."
                ),
                "highlights": [
                    {"label": "Peak Temp", "value": f"{dobj.get('peak_temp_c')}°C"},
                    {"label": "Site", "value": dobj.get("site_name") or "--"},
                    {"label": "Members", "value": str(dobj.get("member_count", 1))},
                ],
                "links": [
                    _link_switch(org_id, ui_host, dobj.get("site_id", ""), dobj.get("id", ""), dobj.get("vc_mac") or dobj.get("mac", ""), dobj["name"]),
                    _link_site(org_id, ui_host, dobj.get("site_id", ""), dobj.get("site_name", "Site")),
                ],
                "context": ctx,
            }
        if dkind == "switch_down":
            return {
                "reply": (
                    f"**{dobj['name']}** (`{dobj.get('model') or 'Switch'}`, {dobj.get('site_name')}) is currently "
                    f"**{dobj.get('status', 'disconnected')}** (IP `{dobj.get('ip') or '--'}`, last seen **{_fmt_local_time(dobj.get('last_seen'), tzinfo, include_date=True)}**)."
                ),
                "highlights": [
                    {"label": "Status", "value": dobj.get("status", "disconnected")},
                    {"label": "Site", "value": dobj.get("site_name") or "--"},
                    {"label": "IP", "value": dobj.get("ip") or "--"},
                ],
                "links": [
                    _link_switch(org_id, ui_host, dobj.get("site_id", ""), dobj.get("id", ""), dobj.get("mac", ""), dobj["name"]),
                    _link_site(org_id, ui_host, dobj.get("site_id", ""), dobj.get("site_name", "Site")),
                ],
                "context": ctx,
            }
        return {
            "reply": (
                f"AP **{dobj['name']}** (`{dobj.get('model') or 'AP'}`, {dobj.get('site_name')}) is **{dobj.get('status', 'connected')}** "
                f"with **{dobj.get('num_clients', 0)}** connected clients (IP `{dobj.get('ip') or '--'}`)."
            ),
            "highlights": [
                {"label": "Status", "value": str(dobj.get("status", "connected"))},
                {"label": "Clients", "value": str(dobj.get("num_clients", 0))},
                {"label": "Site", "value": dobj.get("site_name") or "--"},
            ],
            "links": [
                _link_ap(org_id, ui_host, dobj.get("site_id", ""), dobj.get("id", ""), dobj.get("mac", ""), dobj["name"]),
                _link_site(org_id, ui_host, dobj.get("site_id", ""), dobj.get("site_name", "Site")),
            ],
            "context": ctx,
        }

    # 11. Top Busiest APs
    if any(k in low for k in ("busiest ap", "top ap", "most clients", "busy ap")):
        top_aps = list(snapshot.get("top_aps") or [])
        if mentioned_site:
            top_aps = [a for a in top_aps if (a.get("site_name") or "").lower() == mentioned_site["name"].lower()]
        top_aps = top_aps[:5]
        if not top_aps:
            return {"reply": "No AP client data available yet.", "highlights": [], "links": [], "context": ctx}
        lines = [f"- **#{i+1} {a['name']}** ({a['site_name']}) — **{a.get('num_clients', 0)}** clients (`{a.get('ip') or '--'}`)" for i, a in enumerate(top_aps)]
        links = [_link_ap(org_id, ui_host, a.get("site_id", ""), a.get("id", ""), a.get("mac", ""), a["name"]) for a in top_aps[:4]]
        return {
            "reply": "Top busiest APs right now:\n" + "\n".join(lines),
            "highlights": [{"label": "#1 Busiest AP", "value": f"{top_aps[0]['name']} ({top_aps[0].get('num_clients', 0)} clients)"}],
            "links": links,
            "context": ctx,
        }

    # 11b. Site-level application traffic (Mist Site Insights top-app-by-bytes)
    site_wants_apps, site_req_app, site_app_tokens = _detect_app_query(text)
    if mentioned_site and site_wants_apps:
        _, win_start, win_end, win_label = _detect_time_window(text, now_epoch, tzinfo)
        site_apps = _fetch_site_app_usage(session, api_host, mentioned_site["id"], win_start, win_end)
        site_apps.sort(key=lambda x: -float(x.get("total_bytes") or 0.0))
        tot_site_bytes = sum(float(a.get("total_bytes") or 0.0) for a in site_apps)
        site_lnk = _link_site(org_id, ui_host, mentioned_site["id"], f"{mentioned_site['name']} Insights")
        if site_req_app:
            matched_sa = [
                a for a in site_apps
                if any(tok in a["app"].lower() for tok in site_app_tokens)
            ]
            if matched_sa:
                sum_b = sum(float(a.get("total_bytes") or 0.0) for a in matched_sa)
                pct = (sum_b / tot_site_bytes * 100.0) if tot_site_bytes > 0 else 0.0
                return {
                    "reply": (
                        f"**{mentioned_site['name']}** generated **{_fmt_bytes(sum_b)}** of **{site_req_app}** traffic **{win_label}** "
                        f"({pct:.1f}% of `{_fmt_bytes(tot_site_bytes)}` classified app traffic)."
                    ),
                    "highlights": [
                        {"label": f"{site_req_app} Traffic", "value": _fmt_bytes(sum_b)},
                        {"label": "Share", "value": f"{pct:.1f}%"},
                        {"label": "Site", "value": mentioned_site["name"]},
                    ],
                    "links": [site_lnk],
                    "context": ctx,
                }
            return {
                "reply": f"Mist Site Insights recorded **0 B** of **{site_req_app}** traffic at **{mentioned_site['name']}** **{win_label}**.",
                "highlights": [{"label": f"{site_req_app} Traffic", "value": "0 B"}],
                "links": [site_lnk],
                "context": ctx,
            }
        if site_apps:
            lines = [
                f"- **#{i+1} {a['app']}** — **{_fmt_bytes(a['total_bytes'])}**"
                + (f" ({a['total_bytes'] / tot_site_bytes * 100:.1f}%)" if tot_site_bytes > 0 else "")
                for i, a in enumerate(site_apps[:8])
            ]
            return {
                "reply": f"Top applications at **{mentioned_site['name']}** **{win_label}**:\n" + "\n".join(lines),
                "highlights": [
                    {"label": "#1 App", "value": f"{site_apps[0]['app']} ({_fmt_bytes(site_apps[0]['total_bytes'])})"},
                    {"label": "Classified Total", "value": _fmt_bytes(tot_site_bytes)},
                ],
                "links": [site_lnk],
                "context": ctx,
            }

    # 12. Site-specific stats OR Org Wi-Fi Users / SSID Breakdown / Busiest Sites
    if mentioned_site and any(k in low for k in ("how many", "users", "clients", "eduroam", "rssi", "signal", "status", "stats", "about", "site", "aps", "wifi")):
        s = mentioned_site
        rssi_s = f"{s['avg_rssi']} dBm" if s.get("avg_rssi") is not None else "--"
        return {
            "reply": (
                f"**{s['name']}** currently has **{s.get('total_users', 0):,}** wireless users "
                f"(eduroam: **{s.get('eduroam_users', 0):,}**, UoP Visitor: **{s.get('uop_visitor_users', 0):,}**, "
                f"UoP Connect: **{s.get('uop_connect_users', 0):,}**). "
                f"APs: **{s.get('aps_online', 0)}** online / **{s.get('aps_offline', 0)}** offline · Avg RSSI: `{rssi_s}`."
            ),
            "highlights": [
                {"label": "Total Users", "value": f"{s.get('total_users', 0):,}"},
                {"label": "eduroam", "value": f"{s.get('eduroam_users', 0):,}"},
                {"label": "APs Online", "value": f"{s.get('aps_online', 0)} / {s.get('aps_online', 0) + s.get('aps_offline', 0)}"},
                {"label": "Avg RSSI", "value": rssi_s},
            ],
            "links": [_link_site(org_id, ui_host, s["id"], s["name"])],
            "context": ctx,
        }

    if any(k in low for k in ("busiest site", "top site", "most users", "sites")):
        top_sites = sites[:5]
        lines = [f"- **#{i+1} {s['name']}** — **{s.get('total_users', 0):,}** users (eduroam: {s.get('eduroam_users', 0):,}, APs online: {s.get('aps_online', 0)})" for i, s in enumerate(top_sites)]
        links = [_link_site(org_id, ui_host, s["id"], s["name"]) for s in top_sites[:4] if s.get("id")]
        return {
            "reply": "Busiest sites across the org right now:\n" + "\n".join(lines),
            "highlights": [{"label": "Active Sites", "value": f"{summary.get('active_sites', 0)} / {summary.get('total_sites', 0)}"}],
            "links": links,
            "context": ctx,
            "action_tab": "tab-sites",
        }

    if any(k in low for k in ("how many", "users", "clients", "eduroam", "visitor", "connect", "rssi", "signal", "summary", "overview", "health", "status")):
        total_u = summary.get("total_wireless_users", 0)
        edu = summary.get("eduroam_users", 0)
        vis = summary.get("uop_visitor_users", 0)
        con = summary.get("uop_connect_users", 0)
        rssi_o = f"{summary['avg_rssi']} dBm" if summary.get("avg_rssi") is not None else "--"
        return {
            "reply": (
                f"Live org overview for **{(snapshot.get('org') or {}).get('name', 'Mist Org')}**: "
                f"**{total_u:,}** wireless users online across **{summary.get('active_sites', 0)}** active sites "
                f"(**eduroam**: {edu:,} [{summary.get('eduroam_pct', 0)}%], **UoP Visitor**: {vis:,}, **UoP Connect**: {con:,}). "
                f"Infrastructure: **{summary.get('aps_online', 0)}/{summary.get('aps_total', 0)}** APs online, "
                f"**{summary.get('switches_online', 0)}/{summary.get('switches_total', 0)}** switches online, "
                f"avg RSSI `{rssi_o}`."
            ),
            "highlights": [
                {"label": "Total Wi-Fi Users", "value": f"{total_u:,}"},
                {"label": "eduroam", "value": f"{edu:,} ({summary.get('eduroam_pct', 0)}%)"},
                {"label": "APs Online", "value": f"{summary.get('aps_online', 0)} / {summary.get('aps_total', 0)}"},
                {"label": "Switches Down", "value": str(summary.get("switches_offline", 0))},
            ],
            "links": [],
            "context": ctx,
        }

    # 13. Optional LLM fallback if GEMINI_API_KEY / OPENAI_API_KEY is configured
    llm_reply = _optional_llm_answer(text, snapshot, [])
    if llm_reply:
        return {"reply": llm_reply, "highlights": [], "links": [], "context": ctx}

    # 14. Last resort: if a target token was extracted at all, try live Mist client lookup
    if target:
        return _answer_client_question(
            message=text,
            target=target,
            mode=mode,
            session=session,
            api_host=api_host,
            ui_host=ui_host,
            org_id=org_id,
            snapshot=snapshot,
            tzinfo=tzinfo,
            now_ts=now_epoch,
        )

    return {
        "reply": (
            "I wasn't sure which Mist resource to query for that. Try asking about:\n"
            "- A user/device/IP/MAC: *\"What time did nick.bull first connect to eduroam this morning?\"*\n"
            "- Outages: *\"Which switches or VC members are down?\"*\n"
            "- Thermals & Wi-Fi: *\"What's the hottest VC?\"*, *\"How many users are on eduroam?\"*, *\"What was today's Wi-Fi peak?\"*"
        ),
        "highlights": [],
        "links": [],
        "context": ctx,
    }
