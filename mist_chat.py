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
    r"\b(?:did|is|was|has|does|for|user|username|client|lookup|find|locate|check|about|show(?:\s+me)?)\s+"
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
}

SSID_PATTERNS = [
    ("eduroam", re.compile(r"\beduroam\b", re.IGNORECASE)),
    ("UoP Visitor", re.compile(r"\buop[\s_\-]?visitor\b|\bvisitor\b", re.IGNORECASE)),
    ("UoP Connect", re.compile(r"\buop[\s_\-]?connect\b", re.IGNORECASE)),
]

FOLLOWUP_PRONOUN_RE = re.compile(
    r"\b(?:he|she|they|him|her|them|his|their|it|its|that user|that client|that device|same user|same device)\b",
    re.IGNORECASE,
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

    site_name_map = {str(s["id"]): str(s.get("name") or s["id"]) for s in (snapshot.get("sites") or []) if s.get("id")}

    # If specifically asking about NAC rejects for this user/MAC, check Mist NAC denies directly
    if ask_nac:
        nac_params: Dict[str, Any] = {"duration": "1d" if mist_dur in ("1h", "24h") else mist_dur, "limit": 50}
        if mode == "mac":
            nac_params["mac"] = normalize_mac(target)
        elif mode == "username" or "@" in target or "." in target:
            nac_params["username"] = target
        else:
            nac_params["text"] = target
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
        reply += f" ({len(clients)} devices matched — showing most recent.)"

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
                "- **User / Client lookups**: *\"What time did nick.bull first connect to eduroam this morning?\"*, *\"Where is up123456 connected?\"*, *\"Who has 10.20.1.55?\"*\n"
                "- **Outages & VC health**: *\"Which switches are down?\"*, *\"Any down VC members or PFE faults?\"*, *\"Offline APs in Library\"*\n"
                "- **Thermals**: *\"What's the hottest VC?\"*, *\"Show hottest EX4000/EX4100 switches\"*\n"
                "- **Wi-Fi & Peaks**: *\"How many users are on eduroam?\"*, *\"What was today's Wi-Fi peak?\"*, *\"Top 5 busiest APs\"*\n"
                "- **Alarms, Uplinks & NAC**: *\"Show critical alarms\"*, *\"Any APs under 1Gb?\"*, *\"Was nick.bull rejected by NAC?\"*"
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
