from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

DISPLAY_TIMEZONE = os.getenv("DISPLAY_TIMEZONE", "Europe/London").strip() or "Europe/London"


def _get_display_tz():
    if ZoneInfo is not None:
        try:
            return ZoneInfo(DISPLAY_TIMEZONE)
        except Exception:
            pass
    return timezone.utc


DISPLAY_TZ = _get_display_tz()

ALLOWED_DAYS = (1, 5, 7)
DAY_LABELS = {
    1: "Last 24 Hours",
    5: "Last 5 Days",
    7: "Last 7 Days",
}


class MistRateLimitError(RuntimeError):
    """Raised immediately when Juniper Mist returns HTTP 429 so we stop issuing requests."""


def _to_float(val: Any) -> Optional[float]:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        f = float(val)
        return f if f >= 0 else 0.0
    try:
        f = float(str(val).strip())
        return f if f >= 0 else 0.0
    except (TypeError, ValueError):
        return None


def _parse_interval_sec(val: Any, default_interval: int = 3600) -> int:
    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
        return int(val)
    if isinstance(val, str):
        s = val.strip().lower()
        if s.isdigit():
            v = int(s)
            return v if v > 0 else default_interval
        if len(s) >= 2 and s[:-1].replace(".", "", 1).isdigit():
            num = float(s[:-1])
            unit = s[-1]
            mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}.get(unit)
            if mult and num > 0:
                return int(num * mult)
    return default_interval


def _norm_epoch_sec(ts_val: Any) -> int:
    if ts_val is None or isinstance(ts_val, bool):
        return 0
    if isinstance(ts_val, (int, float)):
        f = float(ts_val)
        if f <= 0:
            return 0
        if f > 1e12:
            f = f / 1000.0
        return int(f)
    if isinstance(ts_val, str):
        s = ts_val.strip()
        if not s:
            return 0
        f = _to_float(s)
        if f is not None and f > 0:
            if f > 1e12:
                f = f / 1000.0
            return int(f)
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            pass
    return 0


def parse_local_datetime_to_epoch(raw: Optional[str]) -> Optional[int]:
    """Parse an epoch timestamp or local ISO datetime (YYYY-MM-DDTHH:MM) in DISPLAY_TZ."""
    s = str(raw or "").strip()
    if not s:
        return None
    if s.isdigit():
        val = int(s)
        if val > 1e12:
            val = val // 1000
        return val if val > 0 else None
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    if len(iso) == 10 and iso[4] == "-" and iso[7] == "-":
        iso = f"{iso}T00:00:00"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise ValueError(f"Invalid date/time format: '{s}'. Expected YYYY-MM-DDTHH:MM.") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=DISPLAY_TZ)
    return int(dt.timestamp())


def _resolve_timestamps(
    payload: Dict[str, Any],
    length: int,
    default_interval: int = 3600,
) -> Tuple[List[int], int]:
    rt_top = payload.get("rt")
    if not isinstance(rt_top, list):
        rt_top = payload.get("timestamps") if isinstance(payload.get("timestamps"), list) else None

    start_sec = _norm_epoch_sec(payload.get("start"))
    end_sec = _norm_epoch_sec(payload.get("end"))
    resp_interval = _parse_interval_sec(payload.get("interval"), default_interval)

    timestamps: List[int] = []
    if isinstance(rt_top, list) and len(rt_top) >= length:
        parsed_rt = [_norm_epoch_sec(rt_top[i]) for i in range(length)]
        if sum(1 for t in parsed_rt if t > 0) > 0:
            timestamps = parsed_rt

    if not timestamps:
        if start_sec > 0:
            timestamps = [start_sec + i * resp_interval for i in range(length)]
        elif end_sec > 0:
            base = end_sec - length * resp_interval
            timestamps = [base + i * resp_interval for i in range(length)]

    step_sec = resp_interval
    valid_ts = [t for t in timestamps if t > 0]
    if len(valid_ts) >= 2:
        diff = valid_ts[1] - valid_ts[0]
        if 60 <= diff <= 86400:
            step_sec = diff

    return timestamps, step_sec


def _parse_site_stats_payload(
    payload: Any,
    default_interval: int = 3600,
) -> List[Tuple[int, float, float, float]]:
    """Parse Mist /sites/{site_id}/insights/site/{site_id}/stats rx_bytes,tx_bytes payload."""
    if not isinstance(payload, dict):
        return []
    rx_arr = payload.get("rx_bytes") if isinstance(payload.get("rx_bytes"), list) else None
    tx_arr = payload.get("tx_bytes") if isinstance(payload.get("tx_bytes"), list) else None
    if rx_arr is None and tx_arr is None:
        return []
    n = max(len(rx_arr or []), len(tx_arr or []))
    if n == 0:
        return []

    timestamps, _ = _resolve_timestamps(payload, n, default_interval=default_interval)
    if len(timestamps) < n:
        return []

    points: List[Tuple[int, float, float, float]] = []
    for i in range(n):
        ts = timestamps[i]
        if ts <= 0:
            continue
        rx_b = (_to_float(rx_arr[i]) if rx_arr is not None and i < len(rx_arr) else None) or 0.0
        tx_b = (_to_float(tx_arr[i]) if tx_arr is not None and i < len(tx_arr) else None) or 0.0
        points.append((ts, rx_b + tx_b, tx_b, rx_b))
    return points


def _fetch_one_site_traffic(
    session: requests.Session,
    api_host: str,
    site_id: str,
    start_ts: int,
    end_ts: int,
    interval_sec: int,
    rate_limit_flag: threading.Event,
) -> Tuple[Optional[List[Tuple[int, float, float, float]]], Optional[str]]:
    """Single strictly read-only GET call per site; aborts cleanly on HTTP 429."""
    if rate_limit_flag.is_set():
        return None, "HTTP 429"

    url = f"{api_host}/api/v1/sites/{site_id}/insights/site/{site_id}/stats"
    params = {
        "start": str(start_ts),
        "end": str(end_ts),
        "interval": str(interval_sec),
        "metrics": "rx_bytes,tx_bytes",
    }
    try:
        resp = session.get(url, params=params, timeout=20)
    except Exception as exc:
        return None, str(exc)

    if resp.status_code == 429:
        rate_limit_flag.set()
        return None, "HTTP 429"

    if resp.status_code == 400 and interval_sec != 3600:
        # If Mist rejects 600s for this window, fall back once to 3600s
        params["interval"] = "3600"
        try:
            resp = session.get(url, params=params, timeout=20)
        except Exception as exc:
            return None, str(exc)
        if resp.status_code == 429:
            rate_limit_flag.set()
            return None, "HTTP 429"

    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"

    try:
        payload = resp.json()
    except Exception as exc:
        return None, f"Invalid JSON: {exc}"

    return _parse_site_stats_payload(payload, default_interval=interval_sec), None


def _load_sites(
    session: requests.Session,
    api_host: str,
    org_id: str,
    site_name_map: Optional[Dict[str, str]] = None,
    active_site_ids: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    """Return (all_sites_map, active_site_ids_to_query). Skips 0-AP sites to save Mist API quota."""
    sites = dict(site_name_map or {})
    query_ids: List[str] = list(active_site_ids or [])

    if not sites or not query_ids:
        resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/stats/sites", params={"limit": 1000}, timeout=20)
        if resp.status_code == 429:
            raise MistRateLimitError("Mist EU API rate limit (5,000 calls/hour) reached. Please wait a few minutes and try again.")
        if resp.status_code == 200:
            raw_stats = resp.json()
            if isinstance(raw_stats, list) and raw_stats:
                scored: List[Tuple[int, int, str]] = []
                for s in raw_stats:
                    if not isinstance(s, dict) or not s.get("id"):
                        continue
                    sid = str(s["id"])
                    if sid not in sites:
                        sites[sid] = str(s.get("name") or sid)
                    num_aps = int(_to_float(s.get("num_aps")) or 0)
                    num_clients = int(_to_float(s.get("num_clients")) or 0)
                    if num_aps > 0 or num_clients > 0:
                        scored.append((num_clients, num_aps, sid))
                if not query_ids and scored:
                    scored.sort(key=lambda t: (-t[0], -t[1], sites.get(t[2], "").lower()))
                    query_ids = [t[2] for t in scored]

    if not sites:
        resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/sites", params={"limit": 1000}, timeout=20)
        if resp.status_code == 429:
            raise MistRateLimitError("Mist EU API rate limit (5,000 calls/hour) reached. Please wait a few minutes and try again.")
        resp.raise_for_status()
        raw = resp.json()
        if isinstance(raw, list):
            for s in raw:
                if isinstance(s, dict) and s.get("id"):
                    sites[str(s["id"])] = str(s.get("name") or s["id"])

    if not query_ids:
        query_ids = [sid for sid, _ in sorted(sites.items(), key=lambda kv: kv[1].lower())]
    else:
        seen = set()
        deduped: List[str] = []
        for sid in query_ids:
            if sid in sites and sid not in seen:
                seen.add(sid)
                deduped.append(sid)
        query_ids = deduped

    return sites, query_ids


def _format_bucket_label(dt: datetime, span_sec: int) -> str:
    if span_sec <= 86400 + 3600:
        return dt.strftime("%H:%M")
    if span_sec <= 7 * 86400 + 3600:
        return dt.strftime("%a %H:%M")
    return dt.strftime("%d %b %H:%M")


def _format_bucket_full_label(dt: datetime, bucket_sec: int) -> str:
    end_dt = datetime.fromtimestamp(int(dt.timestamp()) + bucket_sec, tz=timezone.utc).astimezone(DISPLAY_TZ)
    return f"{dt.strftime('%a %d %b %Y, %H:%M')}–{end_dt.strftime('%H:%M')}"


def _format_custom_period_label(start_dt: datetime, end_dt: datetime) -> str:
    if start_dt.date() == end_dt.date():
        return f"{start_dt.strftime('%a %d %b %Y, %H:%M')}–{end_dt.strftime('%H:%M')}"
    return f"{start_dt.strftime('%a %d %b %H:%M')} – {end_dt.strftime('%a %d %b %H:%M')}"


def collect_traffic_usage(
    session: requests.Session,
    api_host: str,
    org_id: str,
    days: int = 5,
    site_id: Optional[str] = None,
    site_name_map: Optional[Dict[str, str]] = None,
    prioritized_site_ids: Optional[List[str]] = None,
    now_ts: Optional[int] = None,
    start_ts: Optional[int] = None,
    end_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Strictly read-only Mist traffic usage collector using 1 call per active site (rate-limit safe)."""
    now_epoch = int(now_ts if now_ts is not None else time.time())
    is_custom = start_ts is not None or end_ts is not None

    if is_custom:
        resolved_end = int(end_ts) if end_ts is not None else now_epoch
        if resolved_end > now_epoch:
            resolved_end = now_epoch
        resolved_start = int(start_ts) if start_ts is not None else (resolved_end - 86400)
        if resolved_start >= resolved_end:
            raise ValueError("Start date/time must be earlier than end date/time.")
        span_sec = resolved_end - resolved_start
        if span_sec < 1800:
            raise ValueError("Selected time range must be at least 30 minutes.")
        if span_sec > 31 * 86400:
            raise ValueError("Selected time range cannot exceed 31 days.")
        start_ts_val = resolved_start
        end_ts_val = resolved_end
        effective_days = max(1, int(round(span_sec / 86400.0)))
    else:
        if days not in ALLOWED_DAYS:
            days = 5
        end_ts_val = now_epoch
        start_ts_val = end_ts_val - days * 86400
        span_sec = end_ts_val - start_ts_val
        effective_days = days

    if is_custom and span_sec <= 12 * 3600 and (now_epoch - start_ts_val) <= 86400:
        bucket_sec = 600
        granularity_label = "10-min buckets"
    else:
        bucket_sec = 3600
        granularity_label = "Hourly buckets"

    first_bucket = (start_ts_val // bucket_sec) * bucket_sec
    last_bucket = (end_ts_val // bucket_sec) * bucket_sec
    if is_custom and end_ts_val % bucket_sec == 0 and last_bucket > first_bucket:
        last_bucket -= bucket_sec

    dt_start_local = datetime.fromtimestamp(start_ts_val, tz=timezone.utc).astimezone(DISPLAY_TZ)
    dt_end_local = datetime.fromtimestamp(end_ts_val, tz=timezone.utc).astimezone(DISPLAY_TZ)
    duration_label = (
        _format_custom_period_label(dt_start_local, dt_end_local)
        if is_custom
        else DAY_LABELS.get(days, f"Last {days} Days")
    )

    sites_map, active_site_ids = _load_sites(
        session=session,
        api_host=api_host,
        org_id=org_id,
        site_name_map=site_name_map,
        active_site_ids=prioritized_site_ids,
    )

    available_sites = [
        {"id": sid, "name": name}
        for sid, name in sorted(sites_map.items(), key=lambda kv: kv[1].lower())
    ]

    selected_site = (site_id or "").strip()
    if selected_site.lower() in ("", "all"):
        selected_site = "all"
        target_site_ids = active_site_ids
        selected_site_name = "All Sites (Org Total)"
    else:
        if selected_site not in sites_map:
            raise ValueError("Selected site was not found in this Mist organisation.")
        target_site_ids = [selected_site]
        selected_site_name = sites_map[selected_site]

    rate_limit_flag = threading.Event()
    site_series: Dict[str, List[Tuple[int, float, float, float]]] = {}
    sites_failed = 0
    warnings: List[str] = []

    if target_site_ids:
        # Check the first site synchronously first so a 429 stops immediately after 1 call instead of a burst!
        first_sid = target_site_ids[0]
        first_pts, first_err = _fetch_one_site_traffic(
            session, api_host, first_sid, start_ts_val, end_ts_val, bucket_sec, rate_limit_flag
        )
        if rate_limit_flag.is_set():
            raise MistRateLimitError(
                "Mist EU API rate limit (5,000 calls/hour) was reached. Wait a few minutes for the hourly window to recover, then click Refresh."
            )
        if first_pts is not None:
            site_series[first_sid] = first_pts
        else:
            sites_failed += 1

        remaining_ids = target_site_ids[1:]
        if remaining_ids:
            max_workers = min(5, len(remaining_ids))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futs = {
                    pool.submit(
                        _fetch_one_site_traffic,
                        session,
                        api_host,
                        sid,
                        start_ts_val,
                        end_ts_val,
                        bucket_sec,
                        rate_limit_flag,
                    ): sid
                    for sid in remaining_ids
                }
                for fut in as_completed(futs):
                    sid = futs[fut]
                    try:
                        pts, err = fut.result()
                    except Exception:
                        pts, err = None, "request error"
                    if pts is not None:
                        site_series[sid] = pts
                    else:
                        sites_failed += 1

        if rate_limit_flag.is_set():
            if not site_series:
                raise MistRateLimitError(
                    "Mist EU API rate limit (5,000 calls/hour) was reached. Wait a few minutes and click Refresh."
                )
            warnings.append(
                f"Mist EU rate limit (HTTP 429) hit partway through — showing partial data from {len(site_series)} of {len(target_site_ids)} sites."
            )
        elif sites_failed > 0:
            warnings.append(f"{sites_failed} site(s) did not return traffic metrics for this period.")

    # Prepare aligned buckets across the full window
    bucket_totals: Dict[int, List[float]] = {}
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_totals[cursor] = [0.0, 0.0, 0.0]
        cursor += bucket_sec

    top_sites_raw: List[Dict[str, Any]] = []
    sites_with_data = 0

    for sid in target_site_ids:
        pts = site_series.get(sid) or []
        if not pts:
            continue
        site_buckets: Dict[int, List[float]] = {}
        for ts, tot_b, tx_b, rx_b in pts:
            b_ts = (ts // bucket_sec) * bucket_sec
            if b_ts < first_bucket or b_ts > last_bucket:
                continue
            acc = bucket_totals[b_ts]
            acc[0] += tot_b
            acc[1] += tx_b
            acc[2] += rx_b

            s_acc = site_buckets.get(b_ts)
            if s_acc is None:
                site_buckets[b_ts] = [tot_b, tx_b, rx_b]
            else:
                s_acc[0] += tot_b
                s_acc[1] += tx_b
                s_acc[2] += rx_b

        s_tot = sum(v[0] for v in site_buckets.values())
        s_tx = sum(v[1] for v in site_buckets.values())
        s_rx = sum(v[2] for v in site_buckets.values())
        if s_tot > 0:
            sites_with_data += 1
        s_peak_mbps = 0.0
        for b_ts, vals in site_buckets.items():
            eff_sec = max(60, min(bucket_sec, end_ts_val - b_ts)) if b_ts == last_bucket else bucket_sec
            mbps = (vals[0] * 8.0) / eff_sec / 1e6
            if mbps > s_peak_mbps:
                s_peak_mbps = mbps
        s_avg_mbps = (s_tot * 8.0) / max(1, span_sec) / 1e6
        top_sites_raw.append(
            {
                "site_id": sid,
                "site_name": sites_map.get(sid, sid),
                "total_bytes": int(round(s_tot)),
                "tx_bytes": int(round(s_tx)),
                "rx_bytes": int(round(s_rx)),
                "peak_mbps": round(s_peak_mbps, 2),
                "avg_mbps": round(s_avg_mbps, 2),
            }
        )

    # Build time-series points and daily rollups in DISPLAY_TZ
    hourly_points: List[Dict[str, Any]] = []
    daily_map: Dict[str, Dict[str, Any]] = {}

    grand_total_bytes = 0.0
    grand_tx_bytes = 0.0
    grand_rx_bytes = 0.0
    total_elapsed_sec = 0

    peak_mbps = 0.0
    peak_time_label = ""
    peak_short_time = ""
    peak_hour_bytes = 0.0
    peak_hour_time_label = ""

    for b_ts in sorted(bucket_totals.keys()):
        tot_b, tx_b, rx_b = bucket_totals[b_ts]
        is_partial = b_ts == last_bucket and (end_ts_val - b_ts) < (bucket_sec - 60)
        eff_sec = max(60, min(bucket_sec, end_ts_val - b_ts)) if b_ts == last_bucket else bucket_sec

        avg_mbps = (tot_b * 8.0) / eff_sec / 1e6
        tx_mbps = (tx_b * 8.0) / eff_sec / 1e6
        rx_mbps = (rx_b * 8.0) / eff_sec / 1e6

        dt_local = datetime.fromtimestamp(b_ts, tz=timezone.utc).astimezone(DISPLAY_TZ)
        day_key = dt_local.strftime("%Y-%m-%d")
        day_label = dt_local.strftime("%a %d %b")
        full_label = _format_bucket_full_label(dt_local, bucket_sec)
        short_label = dt_local.strftime("%a %d %b, %H:%M")

        grand_total_bytes += tot_b
        grand_tx_bytes += tx_b
        grand_rx_bytes += rx_b
        total_elapsed_sec += eff_sec

        if avg_mbps > peak_mbps:
            peak_mbps = avg_mbps
            peak_time_label = full_label
            peak_short_time = short_label
        if tot_b > peak_hour_bytes:
            peak_hour_bytes = tot_b
            peak_hour_time_label = full_label

        hourly_points.append(
            {
                "ts": b_ts,
                "label": _format_bucket_label(dt_local, span_sec),
                "full_label": full_label,
                "day_key": day_key,
                "total_bytes": int(round(tot_b)),
                "tx_bytes": int(round(tx_b)),
                "rx_bytes": int(round(rx_b)),
                "total_gb": round(tot_b / 1e9, 3),
                "tx_gb": round(tx_b / 1e9, 3),
                "rx_gb": round(rx_b / 1e9, 3),
                "avg_mbps": round(avg_mbps, 2),
                "tx_mbps": round(tx_mbps, 2),
                "rx_mbps": round(rx_mbps, 2),
                "is_partial_hour": is_partial,
            }
        )

        d_entry = daily_map.get(day_key)
        if d_entry is None:
            daily_map[day_key] = {
                "date": day_key,
                "label": day_label,
                "full_label": dt_local.strftime("%A %d %b %Y"),
                "total_bytes": tot_b,
                "tx_bytes": tx_b,
                "rx_bytes": rx_b,
                "peak_mbps": avg_mbps,
                "elapsed_sec": eff_sec,
                "hours_count": 1,
            }
        else:
            d_entry["total_bytes"] += tot_b
            d_entry["tx_bytes"] += tx_b
            d_entry["rx_bytes"] += rx_b
            if avg_mbps > d_entry["peak_mbps"]:
                d_entry["peak_mbps"] = avg_mbps
            d_entry["elapsed_sec"] += eff_sec
            d_entry["hours_count"] += 1

    daily_points: List[Dict[str, Any]] = []
    busiest_day: Optional[Dict[str, Any]] = None
    for d_key in sorted(daily_map.keys()):
        d = daily_map[d_key]
        d_avg_mbps = (d["total_bytes"] * 8.0) / max(1, d["elapsed_sec"]) / 1e6
        item = {
            "date": d["date"],
            "label": d["label"],
            "full_label": d["full_label"],
            "total_bytes": int(round(d["total_bytes"])),
            "tx_bytes": int(round(d["tx_bytes"])),
            "rx_bytes": int(round(d["rx_bytes"])),
            "total_gb": round(d["total_bytes"] / 1e9, 2),
            "tx_gb": round(d["tx_bytes"] / 1e9, 2),
            "rx_gb": round(d["rx_bytes"] / 1e9, 2),
            "peak_mbps": round(d["peak_mbps"], 2),
            "avg_mbps": round(d_avg_mbps, 2),
            "hours_count": d["hours_count"],
        }
        daily_points.append(item)
        if busiest_day is None or item["total_bytes"] > busiest_day["total_bytes"]:
            busiest_day = item

    top_sites_raw.sort(key=lambda s: (-s["total_bytes"], s["site_name"].lower()))
    for s in top_sites_raw:
        s["share_pct"] = (
            round((s["total_bytes"] / grand_total_bytes) * 100.0, 1)
            if grand_total_bytes > 0
            else 0.0
        )

    busiest_site = top_sites_raw[0] if (top_sites_raw and top_sites_raw[0]["total_bytes"] > 0) else None
    has_rx_tx_split = bool(grand_rx_bytes > 0 or grand_tx_bytes > 0)
    avg_mbps_overall = (grand_total_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_tx_mbps_overall = (grand_tx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_rx_mbps_overall = (grand_rx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6

    if grand_total_bytes <= 0 and not warnings:
        if (now_epoch - end_ts_val) > 7 * 86400 or (now_epoch - start_ts_val) > 7 * 86400:
            earliest_dt = datetime.fromtimestamp(now_epoch - 7 * 86400, tz=timezone.utc).astimezone(DISPLAY_TZ)
            warnings.append(
                f"Mist EU returned no stored telemetry for this window — standard Mist Insights retains hourly site traffic for the last 7 days (from {earliest_dt.strftime('%a %d %b %Y, %H:%M')})."
            )

    return {
        "days": effective_days,
        "is_custom": is_custom,
        "duration_label": duration_label,
        "site_id": selected_site,
        "site_name": selected_site_name,
        "timezone": DISPLAY_TIMEZONE,
        "start_ts": start_ts_val,
        "end_ts": end_ts_val,
        "start_local_iso": dt_start_local.strftime("%Y-%m-%dT%H:%M"),
        "end_local_iso": dt_end_local.strftime("%Y-%m-%dT%H:%M"),
        "bucket_seconds": bucket_sec,
        "granularity_label": granularity_label,
        "can_step_next": end_ts_val < (now_epoch - 300),
        "metric_used": "rx_bytes,tx_bytes (site_stats)",
        "metric_kind": "bytes",
        "has_rx_tx_split": has_rx_tx_split,
        "sites_queried": len(target_site_ids),
        "sites_with_data": sites_with_data,
        "sites_failed": sites_failed,
        "available_sites": available_sites,
        "summary": {
            "total_bytes": int(round(grand_total_bytes)),
            "tx_bytes": int(round(grand_tx_bytes)),
            "rx_bytes": int(round(grand_rx_bytes)),
            "avg_mbps": round(avg_mbps_overall, 2),
            "avg_tx_mbps": round(avg_tx_mbps_overall, 2),
            "avg_rx_mbps": round(avg_rx_mbps_overall, 2),
            "peak_mbps": round(peak_mbps, 2),
            "peak_time_label": peak_time_label,
            "peak_short_time": peak_short_time,
            "peak_hour_bytes": int(round(peak_hour_bytes)),
            "peak_hour_time_label": peak_hour_time_label,
            "busiest_day": {
                "date": busiest_day["date"],
                "label": busiest_day["label"],
                "total_bytes": busiest_day["total_bytes"],
                "total_gb": busiest_day["total_gb"],
            }
            if busiest_day and busiest_day["total_bytes"] > 0
            else None,
            "busiest_site": {
                "site_id": busiest_site["site_id"],
                "site_name": busiest_site["site_name"],
                "total_bytes": busiest_site["total_bytes"],
                "share_pct": busiest_site["share_pct"],
            }
            if busiest_site
            else None,
        },
        "hourly_points": hourly_points,
        "daily_points": daily_points,
        "top_sites": top_sites_raw,
        "warnings": warnings,
    }
