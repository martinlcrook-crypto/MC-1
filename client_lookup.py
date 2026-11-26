from concurrent.futures import ThreadPoolExecutor
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests

from nac_rejects import _mist_search_get, format_mac, normalize_mac

IPV4_FULL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
IPV4_PARTIAL_RE = re.compile(r"^\d{1,3}\.\d{1,3}(?:\.\d{0,3}){0,2}$")
HEX_MAC_CANDIDATE_RE = re.compile(r"^[0-9a-fA-F:.\-\s]{4,23}$")

DURATION_MAP = {
    "1h": "1h",
    "24h": "1d",
    "1d": "1d",
    "7d": "7d",
    "30d": "30d",
}


def detect_query_mode(query: str, requested_mode: str = "auto") -> Tuple[str, str]:
    """Return (mode, normalized_query) where mode is one of 'mac', 'ip', 'username', 'hostname', 'text'."""
    raw = (query or "").strip()
    mode = (requested_mode or "auto").strip().lower()
    if mode in ("mac", "ip", "username", "hostname"):
        if mode == "mac":
            cleaned = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
            return "mac", cleaned or raw
        return mode, raw

    # Auto-detect MAC address (full 12 hex chars, or colon/dash/dot-delimited hex bytes)
    if IPV4_FULL_RE.match(raw) or IPV4_PARTIAL_RE.match(raw):
        return "ip", raw

    hex_only = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    has_mac_sep = any(ch in raw for ch in (":", "-", "."))
    if HEX_MAC_CANDIDATE_RE.match(raw) and (
        len(hex_only) == 12 or (has_mac_sep and 4 <= len(hex_only) <= 12)
    ):
        return "mac", hex_only

    if "@" in raw or "\\" in raw:
        return "username", raw

    return "auto", raw


def signal_quality(rssi: Any) -> Dict[str, str]:
    """Classify Wi-Fi RSSI (dBm) into human-readable quality label & badge tone."""
    if not isinstance(rssi, (int, float)) or rssi >= 0 or rssi < -120:
        return {"label": "Unknown", "tone": "neutral"}
    if rssi >= -60:
        return {"label": "Excellent", "tone": "ok"}
    if rssi >= -70:
        return {"label": "Good", "tone": "ok"}
    if rssi >= -79:
        return {"label": "Fair", "tone": "warn"}
    return {"label": "Poor", "tone": "bad"}


def _norm_band(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val.startswith("24") or val == "2.4":
        return "2.4 GHz"
    if val.startswith("5"):
        return "5 GHz"
    if val.startswith("6"):
        return "6 GHz"
    return str(raw or "").strip()


def _norm_proto(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    mapping = {
        "be": "Wi-Fi 7 (be)",
        "ax": "Wi-Fi 6/6E (ax)",
        "ac": "Wi-Fi 5 (ac)",
        "n": "Wi-Fi 4 (n)",
        "a": "Legacy (a)",
        "g": "Legacy (g)",
        "b": "Legacy (b)",
    }
    return mapping.get(val, str(raw or "").strip())


def _first_nonempty(*vals: Any) -> str:
    for v in vals:
        if isinstance(v, list):
            for item in v:
                s = str(item or "").strip()
                if s:
                    return s
        else:
            s = str(v or "").strip()
            if s:
                return s
    return ""


def _parse_int(val: Any) -> Optional[int]:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, (int, float)):
        return int(round(val))
    try:
        s = str(val).strip()
        return int(float(s)) if s else None
    except (TypeError, ValueError):
        return None


def _parse_float(val: Any) -> Optional[float]:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    try:
        s = str(val).strip()
        return float(s) if s else None
    except (TypeError, ValueError):
        return None


def _load_org_lookups(
    session: requests.Session,
    api_host: str,
    org_id: str,
    site_name_map: Optional[Dict[str, str]] = None,
    ap_name_map: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    sites = dict(site_name_map or {})
    aps = dict(ap_name_map or {})

    def fetch_sites():
        if sites:
            return []
        r = session.get(f"{api_host}/api/v1/orgs/{org_id}/sites", timeout=15)
        r.raise_for_status()
        return r.json() if isinstance(r.json(), list) else []

    def fetch_aps():
        if aps:
            return []
        r = session.get(
            f"{api_host}/api/v1/orgs/{org_id}/stats/devices",
            params={"type": "ap", "status": "all", "limit": 1000},
            timeout=20,
        )
        r.raise_for_status()
        return r.json() if isinstance(r.json(), list) else []

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_s = pool.submit(fetch_sites)
        f_a = pool.submit(fetch_aps)
        try:
            for s in f_s.result() or []:
                if isinstance(s, dict) and s.get("id"):
                    sites[str(s["id"])] = str(s.get("name") or s["id"])
        except Exception:
            pass
        try:
            for ap in f_a.result() or []:
                if not isinstance(ap, dict):
                    continue
                mac = normalize_mac(ap.get("mac"))
                name = str(ap.get("name") or "").strip()
                if mac and name:
                    aps[mac] = name
        except Exception:
            pass

    return sites, aps


def _fetch_live_client_stat(
    session: requests.Session,
    api_host: str,
    site_id: str,
    mac_norm: str,
) -> Optional[Dict[str, Any]]:
    if not site_id or not mac_norm:
        return None
    try:
        resp = session.get(
            f"{api_host}/api/v1/sites/{site_id}/stats/clients/{mac_norm}",
            timeout=12,
        )
        if resp.status_code != 200:
            return None
        payload = resp.json()
        if isinstance(payload, dict) and (payload.get("mac") or payload.get("rssi") is not None or payload.get("ssid")):
            return payload
    except Exception:
        pass
    return None


def _build_live_summary(
    live: Dict[str, Any],
    site_id: str,
    sites: Dict[str, str],
    aps: Dict[str, str],
) -> Dict[str, Any]:
    rssi = _parse_int(live.get("rssi"))
    snr = _parse_int(live.get("snr"))
    ap_mac = normalize_mac(live.get("ap_mac") or live.get("ap"))
    ap_name = aps.get(ap_mac) or str(live.get("ap_name") or "").strip() or (format_mac(ap_mac) if ap_mac else "")
    resolved_site = str(live.get("site_id") or site_id or "")
    tx_rate = _parse_float(live.get("tx_rate"))
    rx_rate = _parse_float(live.get("rx_rate"))
    tx_pkts = _parse_int(live.get("tx_pkts")) or 0
    tx_retries = _parse_int(live.get("tx_retries")) or 0
    retry_pct = round((tx_retries / tx_pkts) * 100, 1) if tx_pkts > 0 and tx_retries >= 0 else None

    return {
        "online": True,
        "mac": format_mac(live.get("mac")),
        "hostname": _first_nonempty(live.get("hostname")),
        "username": _first_nonempty(live.get("username")),
        "ip": _first_nonempty(live.get("ip")),
        "ipv6": _first_nonempty(live.get("ipv6")),
        "ssid": _first_nonempty(live.get("ssid")),
        "vlan": _parse_int(live.get("vlan_id") if live.get("vlan_id") is not None else live.get("vlan")),
        "site_id": resolved_site,
        "site_name": sites.get(resolved_site) or resolved_site or "Unknown Site",
        "ap_mac": format_mac(ap_mac) if ap_mac else "",
        "ap_name": ap_name or "Unknown AP",
        "rssi": rssi,
        "snr": snr,
        "signal_quality": signal_quality(rssi),
        "band": _norm_band(live.get("band")),
        "channel": _parse_int(live.get("channel")),
        "channel_width": _parse_int(live.get("channel_width") or live.get("bandwidth")),
        "proto": _norm_proto(live.get("proto")),
        "key_mgmt": _first_nonempty(live.get("key_mgmt")),
        "tx_rate": round(tx_rate, 1) if tx_rate is not None else None,
        "rx_rate": round(rx_rate, 1) if rx_rate is not None else None,
        "tx_bps": _parse_int(live.get("tx_bps")),
        "rx_bps": _parse_int(live.get("rx_bps")),
        "tx_bytes": _parse_int(live.get("tx_bytes")),
        "rx_bytes": _parse_int(live.get("rx_bytes")),
        "tx_retry_pct": retry_pct,
        "uptime": _parse_int(live.get("uptime")),
        "last_seen": _parse_int(live.get("last_seen")),
        "os": _first_nonempty(live.get("os")),
        "family": _first_nonempty(live.get("family")),
        "model": _first_nonempty(live.get("model")),
        "manufacture": _first_nonempty(live.get("manufacture")),
        "dual_band": live.get("dual_band"),
        "is_guest": live.get("is_guest"),
        "power_saving": live.get("power_saving"),
    }


def search_wifi_clients(
    session: requests.Session,
    api_host: str,
    org_id: str,
    query: str,
    mode: str = "auto",
    duration: str = "7d",
    site_name_map: Optional[Dict[str, str]] = None,
    ap_name_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Strictly read-only search for current or past Wi-Fi clients by MAC, IP, username, or hostname."""
    raw_q = (query or "").strip()
    if len(raw_q) < 2:
        raise ValueError("Enter at least 2 characters (MAC address, IP, username, or hostname).")

    mist_duration = DURATION_MAP.get((duration or "7d").strip().lower(), "7d")
    display_duration = "24h" if mist_duration == "1d" else mist_duration
    detected_mode, norm_q = detect_query_mode(raw_q, mode)

    sites, aps = _load_org_lookups(session, api_host, org_id, site_name_map, ap_name_map)
    warnings: List[str] = []

    def safe_search(label: str, path: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            return _mist_search_get(session, api_host, path, params, max_pages=2)
        except Exception as exc:
            warnings.append(f"{label}: {exc}")
            return []

    search_jobs: List[Tuple[str, str, Dict[str, Any]]] = []
    client_path = f"/api/v1/orgs/{org_id}/clients/search"
    session_path = f"/api/v1/orgs/{org_id}/clients/sessions/search"

    wild_q = norm_q if "*" in norm_q else f"*{norm_q}*"

    if detected_mode == "mac":
        mac_param = norm_q if len(norm_q) == 12 else f"{norm_q}*"
        search_jobs.append(("clients(mac)", client_path, {"mac": mac_param, "duration": mist_duration, "limit": 200}))
    elif detected_mode == "ip":
        ip_param = norm_q if IPV4_FULL_RE.match(norm_q) else f"{norm_q}*"
        search_jobs.append(("clients(ip)", client_path, {"ip": ip_param, "duration": mist_duration, "limit": 200}))
    elif detected_mode == "username":
        search_jobs.append(("clients(username)", client_path, {"username": wild_q, "duration": mist_duration, "limit": 200}))
        search_jobs.append(("clients(text)", client_path, {"text": wild_q, "duration": mist_duration, "limit": 200}))
        search_jobs.append(("sessions(username)", session_path, {"client_username": norm_q, "duration": mist_duration, "limit": 200}))
    elif detected_mode == "hostname":
        host_param = norm_q if "*" in norm_q else f"*{norm_q}*"
        search_jobs.append(("clients(hostname)", client_path, {"hostname": host_param, "duration": mist_duration, "limit": 200}))
        search_jobs.append(("clients(text)", client_path, {"text": wild_q, "duration": mist_duration, "limit": 200}))
    else:
        # Auto general search: check text, username, and sessions in parallel
        search_jobs.append(("clients(text)", client_path, {"text": wild_q, "duration": mist_duration, "limit": 200}))
        search_jobs.append(("clients(username)", client_path, {"username": wild_q, "duration": mist_duration, "limit": 200}))
        search_jobs.append(("sessions(username)", session_path, {"client_username": norm_q, "duration": mist_duration, "limit": 200}))

    raw_results: List[Tuple[str, List[Dict[str, Any]]]] = []
    with ThreadPoolExecutor(max_workers=len(search_jobs)) as pool:
        futs = [(lbl, pool.submit(safe_search, lbl, path, params)) for lbl, path, params in search_jobs]
        for lbl, fut in futs:
            raw_results.append((lbl, fut.result()))

    # If username/auto search discovered full realm usernames (e.g. nick.bull@port.ac.uk),
    # query sessions/search once for those exact usernames to catch any session-only MACs.
    if detected_mode in ("username", "auto"):
        extra_usernames: List[str] = []
        norm_low = norm_q.strip("*").lower()
        for lbl, rows in raw_results:
            if not lbl.startswith("clients"):
                continue
            for row in rows:
                cand_vals = []
                if isinstance(row.get("username"), list):
                    cand_vals.extend(row["username"])
                elif row.get("username"):
                    cand_vals.append(row["username"])
                if row.get("last_username"):
                    cand_vals.append(row["last_username"])
                for u in cand_vals:
                    us = str(u or "").strip()
                    if us and norm_low in us.lower() and us.lower() != norm_low and us not in extra_usernames:
                        extra_usernames.append(us)
        if extra_usernames:
            extra_rows = safe_search(
                "sessions(discovered_usernames)",
                session_path,
                {"client_username": ",".join(extra_usernames[:5]), "duration": mist_duration, "limit": 200},
            )
            if extra_rows:
                raw_results.append(("sessions(discovered_usernames)", extra_rows))

    clients_by_mac: Dict[str, Dict[str, Any]] = {}

    for lbl, rows in raw_results:
        is_session = lbl.startswith("sessions")
        for row in rows:
            mac_norm = normalize_mac(row.get("mac") or row.get("client_mac"))
            if not mac_norm:
                continue
            site_id = str(row.get("site_id") or "")
            row_site_ids = [str(s) for s in (row.get("site_ids") or []) if s]
            if site_id and site_id not in row_site_ids:
                row_site_ids.insert(0, site_id)
            ap_mac = normalize_mac(row.get("last_ap") or row.get("ap"))
            ts = _parse_int(row.get("timestamp")) or 0
            connect_ts = _parse_int(row.get("connect")) or 0
            if not connect_ts and is_session and ts > 0:
                dur_val = _parse_float(row.get("duration"))
                if dur_val and dur_val > 0:
                    connect_ts = max(1, int(ts - dur_val))
            row_first_ts = min(t for t in (ts, connect_ts) if t > 0) if (ts > 0 or connect_ts > 0) else 0
            hostname = _first_nonempty(row.get("last_hostname"), row.get("hostname"))
            username = _first_nonempty(
                row.get("last_username"), row.get("username"), row.get("client_username")
            )
            ip = _first_nonempty(row.get("last_ip"), row.get("ip"))
            ssid = _first_nonempty(row.get("last_ssid"), row.get("ssid"))
            vlan = _parse_int(row.get("last_vlan") if row.get("last_vlan") is not None else row.get("vlan"))
            os_val = _first_nonempty(row.get("last_os"), row.get("os"), row.get("client_os"))
            family = _first_nonempty(row.get("last_device"), row.get("family"), row.get("client_family"), row.get("device"))
            model = _first_nonempty(row.get("last_model"), row.get("model"), row.get("client_model"))
            mfg = _first_nonempty(row.get("mfg"), row.get("manufacture"), row.get("client_manufacture"))
            band = _norm_band(row.get("band"))
            proto = _norm_proto(row.get("proto") or row.get("protocol"))
            rssi = _parse_int(row.get("rssi"))

            existing = clients_by_mac.get(mac_norm)
            if existing is None:
                clients_by_mac[mac_norm] = {
                    "mac": format_mac(mac_norm),
                    "mac_raw": mac_norm,
                    "hostname": hostname,
                    "username": username,
                    "ip": ip,
                    "ssid": ssid,
                    "vlan": vlan,
                    "site_id": site_id,
                    "site_name": sites.get(site_id) or site_id or "Unknown Site",
                    "seen_site_ids": list(row_site_ids),
                    "ap_mac": format_mac(ap_mac) if ap_mac else "",
                    "ap_name": aps.get(ap_mac) or (format_mac(ap_mac) if ap_mac else ""),
                    "os": os_val,
                    "family": family,
                    "model": model,
                    "manufacture": mfg,
                    "band": band,
                    "proto": proto,
                    "rssi": rssi,
                    "snr": None,
                    "signal_quality": signal_quality(rssi),
                    "online": False,
                    "first_seen": row_first_ts,
                    "last_seen": ts,
                    "from_session_only": is_session,
                }
            else:
                for sid_item in row_site_ids:
                    if sid_item and sid_item not in existing["seen_site_ids"]:
                        existing["seen_site_ids"].append(sid_item)
                if row_first_ts > 0 and (existing["first_seen"] <= 0 or row_first_ts < existing["first_seen"]):
                    existing["first_seen"] = row_first_ts
                if ts > existing["last_seen"]:
                    existing["last_seen"] = ts
                    if site_id:
                        existing["site_id"] = site_id
                        existing["site_name"] = sites.get(site_id) or site_id
                    if ap_mac:
                        existing["ap_mac"] = format_mac(ap_mac)
                        existing["ap_name"] = aps.get(ap_mac) or format_mac(ap_mac)
                    if ip:
                        existing["ip"] = ip
                    if ssid:
                        existing["ssid"] = ssid
                    if vlan is not None:
                        existing["vlan"] = vlan
                    if rssi is not None:
                        existing["rssi"] = rssi
                        existing["signal_quality"] = signal_quality(rssi)
                for field, val in (
                    ("hostname", hostname),
                    ("username", username),
                    ("ip", ip),
                    ("ssid", ssid),
                    ("os", os_val),
                    ("family", family),
                    ("model", model),
                    ("manufacture", mfg),
                    ("band", band),
                    ("proto", proto),
                ):
                    if not existing.get(field) and val:
                        existing[field] = val
                if existing.get("vlan") is None and vlan is not None:
                    existing["vlan"] = vlan

    matched = sorted(clients_by_mac.values(), key=lambda c: (-c["last_seen"], c["mac"]))

    # Enrich top 15 matched clients with live stats (RSSI, SNR, online status, live AP/band) in parallel
    top_to_probe = matched[:15]
    if top_to_probe:
        with ThreadPoolExecutor(max_workers=8) as pool:
            live_futs = [
                (c, pool.submit(_fetch_live_client_stat, session, api_host, c["site_id"], c["mac_raw"]))
                for c in top_to_probe
                if c.get("site_id")
            ]
            for c, fut in live_futs:
                live = fut.result()
                if live:
                    ls = _build_live_summary(live, c["site_id"], sites, aps)
                    c["online"] = True
                    c["rssi"] = ls["rssi"]
                    c["snr"] = ls["snr"]
                    c["signal_quality"] = ls["signal_quality"]
                    c["band"] = ls["band"] or c["band"]
                    c["proto"] = ls["proto"] or c["proto"]
                    c["channel"] = ls["channel"]
                    c["ssid"] = ls["ssid"] or c["ssid"]
                    c["ip"] = ls["ip"] or c["ip"]
                    c["vlan"] = ls["vlan"] if ls["vlan"] is not None else c["vlan"]
                    c["ap_name"] = ls["ap_name"] or c["ap_name"]
                    c["ap_mac"] = ls["ap_mac"] or c["ap_mac"]
                    c["username"] = ls["username"] or c["username"]
                    c["hostname"] = ls["hostname"] or c["hostname"]
                    if ls["last_seen"]:
                        c["last_seen"] = max(c["last_seen"], ls["last_seen"])

    # Sort online clients first, then most recently seen
    matched.sort(key=lambda c: (0 if c["online"] else 1, -c["last_seen"], c["mac"]))

    return {
        "query": raw_q,
        "detected_mode": detected_mode,
        "duration": display_duration,
        "total": len(matched),
        "clients": matched[:100],
        "warnings": warnings,
    }


def get_wifi_client_detail(
    session: requests.Session,
    api_host: str,
    org_id: str,
    mac: str,
    site_id: Optional[str] = None,
    duration: str = "7d",
    site_name_map: Optional[Dict[str, str]] = None,
    ap_name_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Strictly read-only deep dive for a single Wi-Fi client: live stats + historical events + sessions."""
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        raise ValueError("A valid 12-hex-character MAC address is required.")

    mist_duration = DURATION_MAP.get((duration or "7d").strip().lower(), "7d")
    display_duration = "24h" if mist_duration == "1d" else mist_duration
    sites, aps = _load_org_lookups(session, api_host, org_id, site_name_map, ap_name_map)
    warnings: List[str] = []

    # Step 1: Query org client search for this MAC to discover all sites/IPs/usernames seen over the duration
    org_records: List[Dict[str, Any]] = []
    try:
        org_records = _mist_search_get(
            session,
            api_host,
            f"/api/v1/orgs/{org_id}/clients/search",
            {"mac": mac_norm, "duration": mist_duration, "limit": 50},
            max_pages=1,
        )
    except Exception as exc:
        warnings.append(f"org_client_search: {exc}")

    org_records.sort(key=lambda r: -(_parse_int(r.get("timestamp")) or 0))
    seen_sites: List[str] = []
    if site_id:
        seen_sites.append(site_id)
    for rec in org_records:
        sid = str(rec.get("site_id") or "")
        if sid and sid not in seen_sites:
            seen_sites.append(sid)

    latest_rec = org_records[0] if org_records else {}
    username = _first_nonempty(latest_rec.get("last_username"), latest_rec.get("username"))

    # Step 2: Fetch live stats (trying primary site first, then up to 2 fallback sites), client events, and sessions in parallel
    def fetch_live_across_sites() -> Optional[Tuple[str, Dict[str, Any]]]:
        for sid in seen_sites[:3]:
            stat = _fetch_live_client_stat(session, api_host, sid, mac_norm)
            if stat:
                return sid, stat
        return None

    def fetch_site_events(sid: str) -> List[Dict[str, Any]]:
        try:
            return _mist_search_get(
                session,
                api_host,
                f"/api/v1/sites/{sid}/clients/{mac_norm}/events",
                {"duration": mist_duration, "limit": 200},
                max_pages=2,
            )
        except Exception as exc:
            warnings.append(f"events({sites.get(sid, sid)}): {exc}")
            return []

    def fetch_sessions() -> List[Dict[str, Any]]:
        if not username:
            return []
        try:
            rows = _mist_search_get(
                session,
                api_host,
                f"/api/v1/orgs/{org_id}/clients/sessions/search",
                {"client_username": username, "duration": mist_duration, "limit": 200},
                max_pages=1,
            )
            return [r for r in rows if normalize_mac(r.get("mac") or r.get("client_mac")) == mac_norm]
        except Exception as exc:
            warnings.append(f"sessions: {exc}")
            return []

    with ThreadPoolExecutor(max_workers=5) as pool:
        f_live = pool.submit(fetch_live_across_sites)
        f_sessions = pool.submit(fetch_sessions)
        event_futs = [(sid, pool.submit(fetch_site_events, sid)) for sid in seen_sites[:3]]

        live_hit = f_live.result()
        raw_sessions = f_sessions.result()
        raw_events: List[Tuple[str, Dict[str, Any]]] = []
        for sid, efut in event_futs:
            for ev in efut.result():
                raw_events.append((sid, ev))

    live_summary: Optional[Dict[str, Any]] = None
    if live_hit:
        live_sid, live_raw = live_hit
        live_summary = _build_live_summary(live_raw, live_sid, sites, aps)

    # Normalize & deduplicate events
    events: List[Dict[str, Any]] = []
    seen_ev_keys: Set[Tuple[int, str, str]] = set()
    rssi_series: List[Dict[str, Any]] = []

    for sid, ev in raw_events:
        ts = _parse_int(ev.get("timestamp")) or 0
        ev_type = str(ev.get("type") or "EVENT").strip()
        ap_mac = normalize_mac(ev.get("ap") or ev.get("ap_mac"))
        ap_name = aps.get(ap_mac) or (format_mac(ap_mac) if ap_mac else "")
        ev_key = (ts, ev_type, ap_mac)
        if ev_key in seen_ev_keys:
            continue
        seen_ev_keys.add(ev_key)

        rssi = _parse_int(ev.get("rssi"))
        reason_code = _parse_int(ev.get("reason_code"))
        low_type = ev_type.lower()
        if any(k in low_type for k in ("fail", "reject", "denied", "deauth", "disassoc", "timeout", "stuck", "error", "bad")):
            category = "issue"
        elif any(k in low_type for k in ("roam", "assoc", "join", "connect", "auth", "dhcp")):
            category = "connect"
        else:
            category = "info"

        ev_item = {
            "timestamp": ts,
            "type": ev_type,
            "category": category,
            "site_id": str(ev.get("site_id") or sid),
            "site_name": sites.get(str(ev.get("site_id") or sid)) or sid or "Unknown Site",
            "ap_mac": format_mac(ap_mac) if ap_mac else "",
            "ap_name": ap_name or "Unknown AP",
            "ssid": _first_nonempty(ev.get("ssid")),
            "band": _norm_band(ev.get("band")),
            "channel": _parse_int(ev.get("channel")),
            "proto": _norm_proto(ev.get("proto")),
            "rssi": rssi,
            "reason_code": reason_code,
            "text": _first_nonempty(ev.get("text"), ev.get("reason")),
        }
        events.append(ev_item)
        if rssi is not None and -120 <= rssi < 0 and ts > 0:
            rssi_series.append({"timestamp": ts, "rssi": rssi, "ap_name": ev_item["ap_name"], "type": ev_type})

    events.sort(key=lambda e: -e["timestamp"])
    rssi_series.sort(key=lambda p: p["timestamp"])

    # Normalize sessions
    sessions: List[Dict[str, Any]] = []
    for s in raw_sessions:
        sid = str(s.get("site_id") or "")
        ap_mac = normalize_mac(s.get("ap") or s.get("last_ap"))
        sessions.append(
            {
                "timestamp": _parse_int(s.get("timestamp")) or 0,
                "duration": _parse_int(s.get("duration")),
                "site_id": sid,
                "site_name": sites.get(sid) or sid or "Unknown Site",
                "ap_mac": format_mac(ap_mac) if ap_mac else "",
                "ap_name": aps.get(ap_mac) or (format_mac(ap_mac) if ap_mac else "Unknown AP"),
                "ssid": _first_nonempty(s.get("ssid")),
                "band": _norm_band(s.get("band")),
                "username": _first_nonempty(s.get("client_username"), s.get("username")),
                "ip": _first_nonempty(s.get("ip"), s.get("last_ip")),
                "disconnect_reason": _first_nonempty(s.get("terminate_reason"), s.get("disconnect_reason")),
            }
        )
    sessions.sort(key=lambda x: -x["timestamp"])

    # Build unified client profile (preferring live stats, falling back to latest historical record / events)
    latest_ap_mac = normalize_mac(latest_rec.get("last_ap") or latest_rec.get("ap"))
    latest_ev_rssi = next((e["rssi"] for e in events if e["rssi"] is not None), None)
    eff_rssi = live_summary["rssi"] if (live_summary and live_summary["rssi"] is not None) else (
        _parse_int(latest_rec.get("rssi")) if _parse_int(latest_rec.get("rssi")) is not None else latest_ev_rssi
    )
    primary_site_id = (live_summary["site_id"] if live_summary else "") or (seen_sites[0] if seen_sites else "")

    profile = {
        "mac": format_mac(mac_norm),
        "online": bool(live_summary),
        "hostname": (live_summary["hostname"] if live_summary else "") or _first_nonempty(latest_rec.get("last_hostname"), latest_rec.get("hostname")),
        "username": (live_summary["username"] if live_summary else "") or username,
        "ip": (live_summary["ip"] if live_summary else "") or _first_nonempty(latest_rec.get("last_ip"), latest_rec.get("ip")),
        "ipv6": live_summary["ipv6"] if live_summary else "",
        "ssid": (live_summary["ssid"] if live_summary else "") or _first_nonempty(latest_rec.get("last_ssid"), latest_rec.get("ssid")),
        "vlan": (live_summary["vlan"] if (live_summary and live_summary["vlan"] is not None) else _parse_int(latest_rec.get("last_vlan") if latest_rec.get("last_vlan") is not None else latest_rec.get("vlan"))),
        "site_id": primary_site_id,
        "site_name": sites.get(primary_site_id) or primary_site_id or "Unknown Site",
        "seen_sites": [sites.get(sid) or sid for sid in seen_sites],
        "ap_mac": (live_summary["ap_mac"] if live_summary else "") or (format_mac(latest_ap_mac) if latest_ap_mac else ""),
        "ap_name": (live_summary["ap_name"] if live_summary else "") or aps.get(latest_ap_mac) or (format_mac(latest_ap_mac) if latest_ap_mac else "Unknown AP"),
        "rssi": eff_rssi,
        "snr": live_summary["snr"] if live_summary else None,
        "signal_quality": signal_quality(eff_rssi),
        "band": (live_summary["band"] if live_summary else "") or _norm_band(latest_rec.get("band")),
        "channel": live_summary["channel"] if live_summary else (events[0]["channel"] if events else None),
        "channel_width": live_summary["channel_width"] if live_summary else None,
        "proto": (live_summary["proto"] if live_summary else "") or _norm_proto(latest_rec.get("proto")),
        "key_mgmt": live_summary["key_mgmt"] if live_summary else "",
        "tx_rate": live_summary["tx_rate"] if live_summary else None,
        "rx_rate": live_summary["rx_rate"] if live_summary else None,
        "tx_bytes": live_summary["tx_bytes"] if live_summary else None,
        "rx_bytes": live_summary["rx_bytes"] if live_summary else None,
        "tx_retry_pct": live_summary["tx_retry_pct"] if live_summary else None,
        "uptime": live_summary["uptime"] if live_summary else None,
        "last_seen": (live_summary["last_seen"] if (live_summary and live_summary["last_seen"]) else None)
        or _parse_int(latest_rec.get("timestamp"))
        or (events[0]["timestamp"] if events else None),
        "os": (live_summary["os"] if live_summary else "") or _first_nonempty(latest_rec.get("os")),
        "family": (live_summary["family"] if live_summary else "") or _first_nonempty(latest_rec.get("family"), latest_rec.get("device")),
        "model": (live_summary["model"] if live_summary else "") or _first_nonempty(latest_rec.get("model")),
        "manufacture": (live_summary["manufacture"] if live_summary else "") or _first_nonempty(latest_rec.get("mfg"), latest_rec.get("manufacture")),
    }

    return {
        "duration": display_duration,
        "profile": profile,
        "rssi_series": rssi_series,
        "events": events[:250],
        "sessions": sessions[:100],
        "warnings": warnings,
    }
