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


def mist_get(session: requests.Session, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Strictly read-only GET helper for the Juniper Mist API."""
    url = f"{MIST_API_HOST}{path}"
    resp = session.get(url, params=params, timeout=20)
    resp.raise_for_status()
    return resp.json()


def mist_get_paginated(
    session: requests.Session,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    limit: int = 1000,
    max_pages: int = 10,
) -> List[Dict[str, Any]]:
    """Fetch paginated list endpoints safely."""
    items: List[Dict[str, Any]] = []
    base_params = dict(params or {})
    base_params["limit"] = limit

    for page in range(1, max_pages + 1):
        base_params["page"] = page
        data = mist_get(session, path, params=base_params)
        if not isinstance(data, list):
            break
        items.extend(data)
        if len(data) < limit:
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


def fetch_site_telemetry(
    session: requests.Session, site: Dict[str, Any]
) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
    site_id = site.get("id", "")
    site_name = site.get("name", site_id)
    clients: List[Dict[str, Any]] = []
    aps: List[Dict[str, Any]] = []
    warning: Optional[str] = None

    try:
        clients = mist_get_paginated(session, f"/api/v1/sites/{site_id}/stats/clients")
    except Exception as exc:
        warning = f"Clients fetch failed for {site_name}: {exc}"

    try:
        aps = mist_get_paginated(
            session,
            f"/api/v1/sites/{site_id}/stats/devices",
            params={"type": "ap"},
        )
    except Exception as exc:
        err = f"AP stats fetch failed for {site_name}: {exc}"
        warning = f"{warning}; {err}" if warning else err

    return site_id, clients, aps, warning


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
    sites_raw = mist_get(session, f"/api/v1/orgs/{MIST_ORG_ID}/sites")
    if not isinstance(sites_raw, list):
        sites_raw = []

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
    total_eduroam_users = 0
    ssid_counts: Dict[str, int] = {}
    band_counts: Dict[str, int] = {"2.4 GHz": 0, "5 GHz": 0, "6 GHz": 0, "Other": 0}
    proto_counts: Dict[str, int] = {}
    rssi_values: List[float] = []

    aps_online = 0
    aps_offline = 0
    all_aps_list: List[Dict[str, Any]] = []
    offline_aps: List[Dict[str, Any]] = []
    sites_summary: List[Dict[str, Any]] = []

    for site_id, site in site_map.items():
        site_name = site.get("name", site_id)
        clients = site_clients.get(site_id, [])
        aps = site_aps.get(site_id, [])

        site_eduroam = 0
        site_rssi: List[float] = []

        for c in clients:
            total_wireless_users += 1
            raw_ssid = (c.get("ssid") or "").strip()
            ssid_label = raw_ssid if raw_ssid else "(Unknown)"
            ssid_counts[ssid_label] = ssid_counts.get(ssid_label, 0) + 1

            if raw_ssid.lower() == "eduroam":
                total_eduroam_users += 1
                site_eduroam += 1

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
        for ap in aps:
            status = str(ap.get("status") or "").lower()
            is_online = status == "connected"
            if is_online:
                aps_online += 1
                site_aps_on += 1
            else:
                aps_offline += 1
                site_aps_off += 1
                offline_aps.append(
                    {
                        "name": ap.get("name") or ap.get("mac", "Unnamed AP"),
                        "site_name": site_name,
                        "model": ap.get("model", ""),
                        "mac": ap.get("mac", ""),
                        "status": status or "disconnected",
                    }
                )

            all_aps_list.append(
                {
                    "name": ap.get("name") or ap.get("mac", "Unnamed AP"),
                    "site_name": site_name,
                    "model": ap.get("model", ""),
                    "ip": ap.get("ip", ""),
                    "num_clients": int(ap.get("num_clients") or 0),
                    "status": "connected" if is_online else (status or "disconnected"),
                }
            )

        site_total = len(clients)
        sites_summary.append(
            {
                "id": site_id,
                "name": site_name,
                "total_users": site_total,
                "eduroam_users": site_eduroam,
                "other_users": max(0, site_total - site_eduroam),
                "aps_online": site_aps_on,
                "aps_offline": site_aps_off,
                "avg_rssi": round(sum(site_rssi) / len(site_rssi), 1) if site_rssi else None,
            }
        )

    sites_summary.sort(key=lambda s: (-s["total_users"], s["name"].lower()))
    all_aps_list.sort(key=lambda a: (-a["num_clients"], a["name"].lower()))

    ssids_sorted = sorted(
        [{"name": k, "count": v} for k, v in ssid_counts.items()],
        key=lambda x: (-x["count"], x["name"].lower()),
    )

    protos_sorted = sorted(
        [{"name": k, "count": v} for k, v in proto_counts.items()],
        key=lambda x: (-x["count"], x["name"]),
    )

    eduroam_pct = (
        round((total_eduroam_users / total_wireless_users) * 100, 1)
        if total_wireless_users > 0
        else 0.0
    )

    return {
        "org": {
            "id": MIST_ORG_ID,
            "name": org_info.get("name", "Mist Organization") if isinstance(org_info, dict) else "Mist Organization",
            "api_host": MIST_API_HOST,
        },
        "summary": {
            "total_wireless_users": total_wireless_users,
            "eduroam_users": total_eduroam_users,
            "eduroam_pct": eduroam_pct,
            "other_wireless_users": max(0, total_wireless_users - total_eduroam_users),
            "total_sites": len(sites_summary),
            "active_sites": sum(1 for s in sites_summary if s["total_users"] > 0),
            "aps_online": aps_online,
            "aps_offline": aps_offline,
            "aps_total": aps_online + aps_offline,
            "avg_rssi": round(sum(rssi_values) / len(rssi_values), 1) if rssi_values else None,
        },
        "sites": sites_summary,
        "ssids": ssids_sorted,
        "bands": band_counts,
        "protocols": protos_sorted,
        "top_aps": all_aps_list[:10],
        "offline_aps": offline_aps,
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
