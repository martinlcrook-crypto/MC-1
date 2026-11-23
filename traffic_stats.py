from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
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

_const_metrics_lock = threading.Lock()
_const_metrics_cache: Tuple[float, Dict[str, Any]] = (0.0, {})
_CONST_METRICS_TTL = 3600.0


@dataclass(frozen=True)
class MetricSpec:
    query_metrics: str
    rx_key: Optional[str]
    tx_key: Optional[str]
    total_key: Optional[str]
    kind: str  # "bytes" or "bps"
    unit_scale: float = 1.0
    single_path: bool = False


def _unit_multiplier(unit: Any, kind: str) -> float:
    u = str(unit or "").strip().lower()
    if not u:
        return 1.0
    if kind == "bps":
        if "gbps" in u or "gbit" in u:
            return 1e9
        if "mbps" in u or "mbit" in u:
            return 1e6
        if "kbps" in u or "kbit" in u:
            return 1e3
        return 1.0
    # bytes
    if u in ("tb", "tbyte", "tbytes", "terabytes"):
        return 1e12
    if u in ("gb", "gbyte", "gbytes", "gigabytes"):
        return 1e9
    if u in ("mb", "mbyte", "mbytes", "megabytes"):
        return 1e6
    if u in ("kb", "kbyte", "kbytes", "kilobytes"):
        return 1e3
    return 1.0


def _fetch_const_insight_metrics(
    session: requests.Session, api_host: str
) -> Dict[str, Any]:
    """Read-only fetch of Mist's /api/v1/const/insight_metrics dictionary (cached 1h)."""
    global _const_metrics_cache
    now = time.time()
    with _const_metrics_lock:
        ts, cached = _const_metrics_cache
        if cached and (now - ts) < _CONST_METRICS_TTL:
            return cached

    try:
        resp = session.get(f"{api_host}/api/v1/const/insight_metrics", timeout=12)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data:
                with _const_metrics_lock:
                    _const_metrics_cache = (now, data)
                return data
    except Exception:
        pass
    return {}


def _is_site_metric(meta: Any) -> bool:
    if not isinstance(meta, dict):
        return True
    scopes = meta.get("scopes") or meta.get("scope")
    if isinstance(scopes, list) and scopes:
        return any(str(s).strip().lower() == "site" for s in scopes)
    if isinstance(scopes, str) and scopes.strip():
        return "site" in scopes.strip().lower()
    return True


def _build_metric_candidates(const_metrics: Dict[str, Any]) -> List[MetricSpec]:
    """Order candidate Mist site-level traffic metrics from most informative to broadest fallback."""
    candidates: List[MetricSpec] = []
    seen_queries = set()

    def add(spec: MetricSpec) -> None:
        key = (spec.query_metrics, spec.single_path)
        if key not in seen_queries:
            seen_queries.add(key)
            candidates.append(spec)

    site_keys: Dict[str, Dict[str, Any]] = {}
    if isinstance(const_metrics, dict):
        for k, meta in const_metrics.items():
            if isinstance(k, str) and _is_site_metric(meta):
                site_keys[k.strip()] = meta if isinstance(meta, dict) else {}

    def scale_for(metric_key: str, kind: str) -> float:
        meta = site_keys.get(metric_key) or {}
        return _unit_multiplier(meta.get("unit") or meta.get("units"), kind)

    # 1. Known paired RX/TX metrics that exist in const/insight_metrics
    paired_defs = [
        ("rx_bytes", "tx_bytes", "bytes"),
        ("bytes_rx", "bytes_tx", "bytes"),
        ("rx_bps", "tx_bps", "bps"),
        ("bps_rx", "bps_tx", "bps"),
    ]
    for rx_k, tx_k, kind in paired_defs:
        if rx_k in site_keys and tx_k in site_keys:
            add(
                MetricSpec(
                    query_metrics=f"{rx_k},{tx_k}",
                    rx_key=rx_k,
                    tx_key=tx_k,
                    total_key=None,
                    kind=kind,
                    unit_scale=scale_for(rx_k, kind),
                )
            )

    # 2. Known single combined traffic metrics that exist in const/insight_metrics
    single_defs = [
        ("bytes", "bytes"),
        ("total_bytes", "bytes"),
        ("client_bytes", "bytes"),
        ("bps", "bps"),
        ("bandwidth", "bps"),
        ("throughput", "bps"),
    ]
    for total_k, kind in single_defs:
        if total_k in site_keys:
            add(
                MetricSpec(
                    query_metrics=total_k,
                    rx_key=None,
                    tx_key=None,
                    total_key=total_k,
                    kind=kind,
                    unit_scale=scale_for(total_k, kind),
                )
            )

    # 3. Any additional discovered site-scoped byte/bps metrics from const/insight_metrics
    exclude_tokens = ("pkt", "packet", "err", "drop", "retry", "util", "bcast", "mcast", "wired", "wan", "dhcp", "dns")
    for k, meta in sorted(site_keys.items()):
        low = k.lower()
        if any(tok in low for tok in exclude_tokens):
            continue
        if "bytes" in low and not low.startswith(("rx_", "tx_")):
            add(MetricSpec(query_metrics=k, rx_key=None, tx_key=None, total_key=k, kind="bytes", unit_scale=scale_for(k, "bytes")))
        elif ("bps" in low or "bandwidth" in low) and not low.startswith(("rx_", "tx_")):
            add(MetricSpec(query_metrics=k, rx_key=None, tx_key=None, total_key=k, kind="bps", unit_scale=scale_for(k, "bps")))

    # 4. Standard built-in fallback specs (used if const/insight_metrics was empty or omitted them)
    add(MetricSpec(query_metrics="rx_bytes,tx_bytes", rx_key="rx_bytes", tx_key="tx_bytes", total_key=None, kind="bytes"))
    add(MetricSpec(query_metrics="bytes", rx_key=None, tx_key=None, total_key="bytes", kind="bytes"))
    add(MetricSpec(query_metrics="rx_bps,tx_bps", rx_key="rx_bps", tx_key="tx_bps", total_key=None, kind="bps"))
    add(MetricSpec(query_metrics="bps", rx_key=None, tx_key=None, total_key="bps", kind="bps"))
    add(MetricSpec(query_metrics="bandwidth", rx_key=None, tx_key=None, total_key="bandwidth", kind="bps"))

    # 5. Single-metric path fallback (/api/v1/sites/{site_id}/insights/{metric})
    add(MetricSpec(query_metrics="bytes", rx_key=None, tx_key=None, total_key="bytes", kind="bytes", single_path=True))
    add(MetricSpec(query_metrics="bps", rx_key=None, tx_key=None, total_key="bps", kind="bps", single_path=True))

    return candidates


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


def _extract_array_from_field(payload: Dict[str, Any], key: Optional[str]) -> Tuple[Optional[List[Any]], Optional[List[Any]]]:
    """Return (values_list, optional_rt_list) for a given metric key in Mist /insights JSON."""
    if not key or key not in payload:
        return None, None
    raw = payload.get(key)
    if isinstance(raw, list):
        return raw, None
    if isinstance(raw, dict):
        for list_key in ("data", "values", "sum", "avg", "series"):
            if isinstance(raw.get(list_key), list):
                rt = raw.get("rt") if isinstance(raw.get("rt"), list) else None
                return raw[list_key], rt
    return None, None


def _extract_site_series(
    payload: Any,
    spec: MetricSpec,
    default_interval: int = 3600,
) -> Tuple[List[Tuple[int, float, float, float]], bool]:
    """Parse Mist site insights payload into [(ts, total_bytes, tx_bytes, rx_bytes), ...].

    Returns (points, parsed_ok) where parsed_ok is True if the response contained a recognizable
    metric structure matching `spec`.
    """
    if not isinstance(payload, dict):
        return [], False

    # Format A: row-oriented `results` list
    if isinstance(payload.get("results"), list):
        results = payload["results"]
        resp_interval = int(_to_float(payload.get("interval")) or default_interval)
        if resp_interval <= 0:
            resp_interval = default_interval
        points: List[Tuple[int, float, float, float]] = []
        matched_any_field = len(results) == 0
        for row in results:
            if not isinstance(row, dict):
                continue
            ts_raw = row.get("ts") or row.get("timestamp") or row.get("rt") or row.get("time")
            ts_f = _to_float(ts_raw)
            if ts_f is None or ts_f <= 0:
                continue
            ts = int(ts_f)
            if spec.rx_key and spec.tx_key:
                has_rx = spec.rx_key in row
                has_tx = spec.tx_key in row
                if not (has_rx or has_tx):
                    continue
                matched_any_field = True
                rx_val = (_to_float(row.get(spec.rx_key)) or 0.0) * spec.unit_scale
                tx_val = (_to_float(row.get(spec.tx_key)) or 0.0) * spec.unit_scale
                if spec.kind == "bps":
                    rx_b = rx_val * resp_interval / 8.0
                    tx_b = tx_val * resp_interval / 8.0
                else:
                    rx_b, tx_b = rx_val, tx_val
                points.append((ts, rx_b + tx_b, tx_b, rx_b))
            elif spec.total_key:
                val_key = spec.total_key if spec.total_key in row else ("value" if "value" in row else None)
                if val_key is None:
                    continue
                matched_any_field = True
                tot_val = (_to_float(row.get(val_key)) or 0.0) * spec.unit_scale
                tot_b = (tot_val * resp_interval / 8.0) if spec.kind == "bps" else tot_val
                points.append((ts, tot_b, 0.0, 0.0))
        return points, matched_any_field

    # Format B: columnar Mist insights response
    rt_top = payload.get("rt")
    if not isinstance(rt_top, list):
        rt_top = payload.get("timestamps") if isinstance(payload.get("timestamps"), list) else None

    start_val = _to_float(payload.get("start"))
    resp_interval = int(_to_float(payload.get("interval")) or default_interval)
    if resp_interval <= 0:
        resp_interval = default_interval

    def resolve_timestamps(length: int, rt_override: Optional[List[Any]]) -> List[int]:
        rt_src = rt_override if isinstance(rt_override, list) and len(rt_override) >= length else rt_top
        if isinstance(rt_src, list) and len(rt_src) >= length:
            out: List[int] = []
            for i in range(length):
                t = _to_float(rt_src[i])
                out.append(int(t) if t is not None else 0)
            return out
        if start_val is not None and start_val > 0:
            base = int(start_val)
            return [base + i * resp_interval for i in range(length)]
        return []

    def infer_step(timestamps: List[int]) -> int:
        if len(timestamps) >= 2:
            diff = timestamps[1] - timestamps[0]
            if 60 <= diff <= 86400:
                return diff
        return resp_interval

    if spec.rx_key and spec.tx_key:
        rx_arr, rx_rt = _extract_array_from_field(payload, spec.rx_key)
        tx_arr, tx_rt = _extract_array_from_field(payload, spec.tx_key)
        if rx_arr is None and tx_arr is None:
            return [], False
        n = max(len(rx_arr or []), len(tx_arr or []))
        if n == 0:
            return [], True
        timestamps = resolve_timestamps(n, rx_rt or tx_rt)
        if len(timestamps) < n:
            return [], False
        step_sec = infer_step(timestamps)
        points = []
        for i in range(n):
            ts = timestamps[i]
            if ts <= 0:
                continue
            rx_raw = (_to_float(rx_arr[i]) if rx_arr is not None and i < len(rx_arr) else None) or 0.0
            tx_raw = (_to_float(tx_arr[i]) if tx_arr is not None and i < len(tx_arr) else None) or 0.0
            rx_val = rx_raw * spec.unit_scale
            tx_val = tx_raw * spec.unit_scale
            if spec.kind == "bps":
                rx_b = rx_val * step_sec / 8.0
                tx_b = tx_val * step_sec / 8.0
            else:
                rx_b, tx_b = rx_val, tx_val
            points.append((ts, rx_b + tx_b, tx_b, rx_b))
        return points, True

    # Single combined metric
    tot_arr, tot_rt = _extract_array_from_field(payload, spec.total_key)
    if tot_arr is None:
        # Some single-metric /insights/{metric} endpoints return `values` or `data` directly
        for fallback_key in ("values", "data", "bytes", "bps"):
            if isinstance(payload.get(fallback_key), list):
                tot_arr = payload[fallback_key]
                break
    if tot_arr is None:
        return [], False
    n = len(tot_arr)
    if n == 0:
        return [], True
    timestamps = resolve_timestamps(n, tot_rt)
    if len(timestamps) < n:
        return [], False
    step_sec = infer_step(timestamps)
    points = []
    for i in range(n):
        ts = timestamps[i]
        if ts <= 0:
            continue
        raw_v = (_to_float(tot_arr[i]) or 0.0) * spec.unit_scale
        tot_b = (raw_v * step_sec / 8.0) if spec.kind == "bps" else raw_v
        points.append((ts, tot_b, 0.0, 0.0))
    return points, True


def _query_site_insights(
    session: requests.Session,
    api_host: str,
    site_id: str,
    spec: MetricSpec,
    start_ts: int,
    end_ts: int,
    interval_str: str = "1h",
) -> Tuple[Optional[List[Tuple[int, float, float, float]]], Optional[str]]:
    """Strictly read-only GET query to Mist site insights for one site."""
    if spec.single_path:
        url = f"{api_host}/api/v1/sites/{site_id}/insights/{spec.query_metrics}"
        params = {"start": str(start_ts), "end": str(end_ts), "interval": interval_str}
    else:
        url = f"{api_host}/api/v1/sites/{site_id}/insights"
        params = {
            "metrics": spec.query_metrics,
            "start": str(start_ts),
            "end": str(end_ts),
            "interval": interval_str,
        }
    try:
        resp = session.get(url, params=params, timeout=20)
    except Exception as exc:
        return None, str(exc)

    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"

    try:
        payload = resp.json()
    except Exception as exc:
        return None, f"Invalid JSON: {exc}"

    points, ok = _extract_site_series(payload, spec, default_interval=3600)
    if not ok:
        return None, f"Metric '{spec.query_metrics}' not present in response"
    return points, None


def _load_sites(
    session: requests.Session,
    api_host: str,
    org_id: str,
    site_name_map: Optional[Dict[str, str]] = None,
    prioritized_site_ids: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    sites = dict(site_name_map or {})
    if not sites:
        resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/sites", params={"limit": 1000}, timeout=20)
        resp.raise_for_status()
        raw = resp.json()
        if isinstance(raw, list):
            for s in raw:
                if isinstance(s, dict) and s.get("id"):
                    sites[str(s["id"])] = str(s.get("name") or s["id"])

    ordered_ids: List[str] = []
    seen = set()
    for sid in prioritized_site_ids or []:
        if sid in sites and sid not in seen:
            seen.add(sid)
            ordered_ids.append(sid)
    for sid, _ in sorted(sites.items(), key=lambda kv: kv[1].lower()):
        if sid not in seen:
            seen.add(sid)
            ordered_ids.append(sid)

    return sites, ordered_ids


def _format_hour_label(dt: datetime, days: int) -> str:
    if days <= 1:
        return dt.strftime("%H:%M")
    return dt.strftime("%a %H:%M")


def _format_hour_full_label(dt: datetime) -> str:
    end_hour = (dt.hour + 1) % 24
    return f"{dt.strftime('%a %d %b %Y, %H:00')}–{end_hour:02d}:00"


def collect_traffic_usage(
    session: requests.Session,
    api_host: str,
    org_id: str,
    days: int = 5,
    site_id: Optional[str] = None,
    site_name_map: Optional[Dict[str, str]] = None,
    prioritized_site_ids: Optional[List[str]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Strictly read-only Mist traffic usage collector across the last N days (default 5)."""
    if days not in ALLOWED_DAYS:
        days = 5

    end_ts = int(now_ts if now_ts is not None else time.time())
    start_ts = end_ts - days * 86400
    first_bucket = (start_ts // 3600) * 3600
    last_bucket = (end_ts // 3600) * 3600

    sites_map, ordered_site_ids = _load_sites(
        session=session,
        api_host=api_host,
        org_id=org_id,
        site_name_map=site_name_map,
        prioritized_site_ids=prioritized_site_ids,
    )

    available_sites = [
        {"id": sid, "name": name}
        for sid, name in sorted(sites_map.items(), key=lambda kv: kv[1].lower())
    ]

    selected_site = (site_id or "").strip()
    if selected_site.lower() in ("", "all"):
        selected_site = "all"
        target_site_ids = ordered_site_ids
        selected_site_name = "All Sites (Org Total)"
    else:
        if selected_site not in sites_map:
            raise ValueError("Selected site was not found in this Mist organisation.")
        target_site_ids = [selected_site]
        selected_site_name = sites_map[selected_site]

    const_metrics = _fetch_const_insight_metrics(session, api_host)
    candidates = _build_metric_candidates(const_metrics)

    warnings: List[str] = []
    chosen_spec: Optional[MetricSpec] = None
    prefetched: Dict[str, List[Tuple[int, float, float, float]]] = {}

    # Probe active site(s) to discover the exact working Mist traffic metric on this cloud
    probe_sites = target_site_ids[:3]
    best_zero_spec: Optional[MetricSpec] = None
    best_zero_prefetched: Dict[str, List[Tuple[int, float, float, float]]] = {}

    for spec in candidates:
        spec_hits: Dict[str, List[Tuple[int, float, float, float]]] = {}
        total_nonzero = 0.0
        any_ok = False
        for sid in probe_sites:
            pts, err = _query_site_insights(session, api_host, sid, spec, start_ts, end_ts, "1h")
            if pts is not None:
                any_ok = True
                spec_hits[sid] = pts
                total_nonzero += sum(p[1] for p in pts)
                if total_nonzero > 0:
                    break
        if any_ok and total_nonzero > 0:
            chosen_spec = spec
            prefetched = spec_hits
            break
        if any_ok and best_zero_spec is None:
            best_zero_spec = spec
            best_zero_prefetched = spec_hits

    if chosen_spec is None and best_zero_spec is not None:
        chosen_spec = best_zero_spec
        prefetched = best_zero_prefetched

    if chosen_spec is None:
        warnings.append(
            "Mist Insights did not return a recognized site traffic metric (tried rx_bytes/tx_bytes, bytes, rx_bps/tx_bps, bps, bandwidth)."
        )
        chosen_spec = candidates[0]

    # Fetch remaining sites in parallel
    site_series: Dict[str, List[Tuple[int, float, float, float]]] = dict(prefetched)
    remaining_ids = [sid for sid in target_site_ids if sid not in site_series]
    sites_failed = 0

    if remaining_ids and not warnings:
        max_workers = min(10, len(remaining_ids))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futs = {
                pool.submit(_query_site_insights, session, api_host, sid, chosen_spec, start_ts, end_ts, "1h"): sid
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

    if sites_failed > 0:
        warnings.append(f"{sites_failed} site(s) did not return traffic metrics for this period.")

    # Prepare aligned hourly buckets across the full window
    bucket_totals: Dict[int, List[float]] = {}
    cursor = first_bucket
    while cursor <= last_bucket:
        bucket_totals[cursor] = [0.0, 0.0, 0.0]  # [total_bytes, tx_bytes, rx_bytes]
        cursor += 3600

    top_sites_raw: List[Dict[str, Any]] = []
    sites_with_data = 0

    for sid in target_site_ids:
        pts = site_series.get(sid) or []
        if not pts:
            continue
        site_buckets: Dict[int, List[float]] = {}
        for ts, tot_b, tx_b, rx_b in pts:
            b_ts = (ts // 3600) * 3600
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
            eff_sec = max(60, min(3600, end_ts - b_ts)) if b_ts == last_bucket else 3600
            mbps = (vals[0] * 8.0) / eff_sec / 1e6
            if mbps > s_peak_mbps:
                s_peak_mbps = mbps
        s_avg_mbps = (s_tot * 8.0) / max(1, days * 86400) / 1e6
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

    # Build hourly points and daily rollups in DISPLAY_TZ
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
        is_partial = b_ts == last_bucket and (end_ts - b_ts) < 3540
        eff_sec = max(60, min(3600, end_ts - b_ts)) if b_ts == last_bucket else 3600

        avg_mbps = (tot_b * 8.0) / eff_sec / 1e6
        tx_mbps = (tx_b * 8.0) / eff_sec / 1e6
        rx_mbps = (rx_b * 8.0) / eff_sec / 1e6

        dt_local = datetime.fromtimestamp(b_ts, tz=timezone.utc).astimezone(DISPLAY_TZ)
        day_key = dt_local.strftime("%Y-%m-%d")
        day_label = dt_local.strftime("%a %d %b")
        full_label = _format_hour_full_label(dt_local)
        short_label = dt_local.strftime("%a %d %b, %H:00")

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
                "label": _format_hour_label(dt_local, days),
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
    has_rx_tx_split = bool(chosen_spec.rx_key and chosen_spec.tx_key and (grand_rx_bytes > 0 or grand_tx_bytes > 0))
    avg_mbps_overall = (grand_total_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_tx_mbps_overall = (grand_tx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_rx_mbps_overall = (grand_rx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6

    return {
        "days": days,
        "duration_label": DAY_LABELS.get(days, f"Last {days} Days"),
        "site_id": selected_site,
        "site_name": selected_site_name,
        "timezone": DISPLAY_TIMEZONE,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "metric_used": chosen_spec.query_metrics,
        "metric_kind": chosen_spec.kind,
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
