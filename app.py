from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory
import requests


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


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MIST_API_HOST = os.getenv("MIST_API_HOST", "https://api.eu.mist.com").rstrip("/")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "").strip()
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "").strip()
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "60"))
MIN_REFRESH_INTERVAL = 15

app = Flask(__name__, static_folder=None)

_cache_lock = threading.Lock()
_cache_data: Optional[Dict[str, Any]] = None
_cache_timestamp: float = 0.0


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


@app.get("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.get("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "read_only": True,
            "api_host": MIST_API_HOST,
            "configured": bool(MIST_ORG_ID and MIST_API_TOKEN),
        }
    )


@app.get("/api/stats")
def api_stats():
    global _cache_data, _cache_timestamp
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
            return jsonify(payload)

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

    payload = dict(fresh_data)
    payload["cached"] = False
    payload["cache_age_seconds"] = 0
    return jsonify(payload)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
