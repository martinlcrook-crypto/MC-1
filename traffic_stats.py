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
    # "site_stats": GET /api/v1/sites/{site_id}/insights/site/{site_id}/stats?start=...&end=...&interval=3600&metrics=...
    # "path":       GET /api/v1/sites/{site_id}/insights/{total_key}?start=...&end=...&interval=3600
    # "paired_path":GET /api/v1/sites/{site_id}/insights/{rx_key} AND /insights/{tx_key}
    mode: str = "site_stats"


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
    scopes = meta.get("report_scopes") or meta.get("scopes") or meta.get("scope")
    if isinstance(scopes, list) and scopes:
        return any(str(s).strip().lower() == "site" for s in scopes)
    if isinstance(scopes, str) and scopes.strip():
        return "site" in scopes.strip().lower()
    return True


def _build_metric_candidates(const_metrics: Dict[str, Any]) -> List[MetricSpec]:
    """Order Mist site-level traffic endpoints starting with /insights/site/{site_id}/stats."""
    candidates: List[MetricSpec] = []
    seen = set()

    def add(spec: MetricSpec) -> None:
        key = (spec.mode, spec.query_metrics)
        if key not in seen:
            seen.add(key)
            candidates.append(spec)

    site_keys: Dict[str, Dict[str, Any]] = {}
    if isinstance(const_metrics, dict):
        for k, meta in const_metrics.items():
            if isinstance(k, str) and _is_site_metric(meta):
                site_keys[k.strip()] = meta if isinstance(meta, dict) else {}

    def scale_for(metric_key: str, kind: str) -> float:
        meta = site_keys.get(metric_key) or {}
        return _unit_multiplier(meta.get("unit") or meta.get("units"), kind)

    # 1. Primary Mist Portal endpoint: GET /api/v1/sites/{site_id}/insights/site/{site_id}/stats
    #    Returns {"rt": [...], "rx_bytes": [...], "tx_bytes": [...]} in a single call per site!
    add(
        MetricSpec(
            query_metrics="rx_bytes,tx_bytes",
            rx_key="rx_bytes",
            tx_key="tx_bytes",
            total_key=None,
            kind="bytes",
            unit_scale=scale_for("rx_bytes", "bytes"),
            mode="site_stats",
        )
    )
    add(
        MetricSpec(
            query_metrics="bytes",
            rx_key=None,
            tx_key=None,
            total_key="bytes",
            kind="bytes",
            unit_scale=scale_for("bytes", "bytes"),
            mode="site_stats",
        )
    )
    add(
        MetricSpec(
            query_metrics="rx_bps,tx_bps",
            rx_key="rx_bps",
            tx_key="tx_bps",
            total_key=None,
            kind="bps",
            unit_scale=scale_for("rx_bps", "bps"),
            mode="site_stats",
        )
    )
    add(
        MetricSpec(
            query_metrics="bps",
            rx_key=None,
            tx_key=None,
            total_key="bps",
            kind="bps",
            unit_scale=scale_for("bps", "bps"),
            mode="site_stats",
        )
    )

    # 2. Secondary Mist path form: GET /api/v1/sites/{site_id}/insights/{metric}
    add(
        MetricSpec(
            query_metrics="bytes",
            rx_key=None,
            tx_key=None,
            total_key="bytes",
            kind="bytes",
            unit_scale=scale_for("bytes", "bytes"),
            mode="path",
        )
    )
    add(
        MetricSpec(
            query_metrics="rx_bytes,tx_bytes",
            rx_key="rx_bytes",
            tx_key="tx_bytes",
            total_key=None,
            kind="bytes",
            unit_scale=scale_for("rx_bytes", "bytes"),
            mode="paired_path",
        )
    )
    add(
        MetricSpec(
            query_metrics="bps",
            rx_key=None,
            tx_key=None,
            total_key="bps",
            kind="bps",
            unit_scale=scale_for("bps", "bps"),
            mode="path",
        )
    )
    add(
        MetricSpec(
            query_metrics="rx_bps,tx_bps",
            rx_key="rx_bps",
            tx_key="tx_bps",
            total_key=None,
            kind="bps",
            unit_scale=scale_for("rx_bps", "bps"),
            mode="paired_path",
        )
    )

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
        # Parse ISO-8601 strings (e.g. "2026-11-19T12:00:00Z" or "2026-11-19 12:00:00")
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            pass
    return 0


def _extract_array_from_field(payload: Dict[str, Any], key: Optional[str]) -> Tuple[Optional[List[Any]], Optional[List[Any]]]:
    """Return (values_list, optional_rt_list) for a given metric key in Mist /insights JSON."""
    if not key or key not in payload:
        return None, None
    raw = payload.get(key)
    if isinstance(raw, list):
        return raw, None
    if isinstance(raw, dict):
        for list_key in ("data", "values", "results", "sum", "avg", "series"):
            if isinstance(raw.get(list_key), list):
                rt = raw.get("rt") if isinstance(raw.get("rt"), list) else None
                return raw[list_key], rt
    return None, None


def _resolve_timestamps(
    payload: Dict[str, Any],
    length: int,
    default_interval: int = 3600,
    rt_override: Optional[List[Any]] = None,
    fallback_start: int = 0,
) -> Tuple[List[int], int]:
    rt_top = payload.get("rt")
    if not isinstance(rt_top, list):
        rt_top = payload.get("timestamps") if isinstance(payload.get("timestamps"), list) else None

    start_sec = _norm_epoch_sec(payload.get("start"))
    end_sec = _norm_epoch_sec(payload.get("end"))
    resp_interval = _parse_interval_sec(payload.get("interval"), default_interval)

    rt_src = rt_override if isinstance(rt_override, list) and len(rt_override) >= length else rt_top
    timestamps: List[int] = []
    if isinstance(rt_src, list) and len(rt_src) >= length:
        parsed_rt = [_norm_epoch_sec(rt_src[i]) for i in range(length)]
        if sum(1 for t in parsed_rt if t > 0) > 0:
            timestamps = parsed_rt

    if not timestamps:
        if start_sec > 0:
            timestamps = [start_sec + i * resp_interval for i in range(length)]
        elif end_sec > 0:
            base = end_sec - length * resp_interval
            timestamps = [base + i * resp_interval for i in range(length)]
        elif fallback_start > 0:
            timestamps = [fallback_start + i * resp_interval for i in range(length)]

    step_sec = resp_interval
    valid_ts = [t for t in timestamps if t > 0]
    if len(valid_ts) >= 2:
        diff = valid_ts[1] - valid_ts[0]
        if 60 <= diff <= 86400:
            step_sec = diff

    return timestamps, step_sec


def _extract_single_value_series(
    payload: Any,
    metric_key: Optional[str],
    kind: str,
    unit_scale: float = 1.0,
    default_interval: int = 3600,
) -> Tuple[List[Tuple[int, float]], bool]:
    """Parse a single Mist /insights/{metric} response into [(ts, bytes_val), ...]."""
    if not isinstance(payload, dict):
        return [], False

    # Case 1: Mist `results` array (numbers or dicts)
    if isinstance(payload.get("results"), list):
        results = payload["results"]
        if len(results) == 0:
            return [], True

        non_null = [x for x in results if x is not None]
        if not non_null:
            return [], True

        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in non_null):
            timestamps, step_sec = _resolve_timestamps(payload, len(results), default_interval)
            if len(timestamps) < len(results):
                return [], False
            out: List[Tuple[int, float]] = []
            for i, raw_v in enumerate(results):
                ts = timestamps[i]
                if ts <= 0:
                    continue
                val = (_to_float(raw_v) or 0.0) * unit_scale
                b_val = (val * step_sec / 8.0) if kind == "bps" else val
                out.append((ts, b_val))
            return out, True

        if any(isinstance(x, dict) for x in non_null):
            timestamps, step_sec = _resolve_timestamps(payload, len(results), default_interval)
            out = []
            matched = False
            candidate_keys = [k for k in (metric_key, "bytes", "total_bytes", "value", "sum", "bps", "bandwidth") if k]
            for i, row in enumerate(results):
                if not isinstance(row, dict):
                    continue
                ts = _norm_epoch_sec(row.get("ts") or row.get("timestamp") or row.get("rt") or row.get("time"))
                if ts <= 0 and i < len(timestamps):
                    ts = timestamps[i]
                if ts <= 0:
                    continue
                chosen_k = next((ck for ck in candidate_keys if ck in row), None)
                if chosen_k is None:
                    continue
                matched = True
                val = (_to_float(row.get(chosen_k)) or 0.0) * unit_scale
                b_val = (val * step_sec / 8.0) if kind == "bps" else val
                out.append((ts, b_val))
            return out, matched

    # Case 2: Columnar array keyed by metric_key or values/data
    arr, rt_override = _extract_array_from_field(payload, metric_key)
    if arr is None:
        for fallback_key in ("values", "data", "bytes", "bps"):
            if isinstance(payload.get(fallback_key), list):
                arr = payload[fallback_key]
                break
    if arr is None:
        return [], False
    if len(arr) == 0:
        return [], True
    timestamps, step_sec = _resolve_timestamps(payload, len(arr), default_interval, rt_override)
    if len(timestamps) < len(arr):
        return [], False
    out = []
    for i, raw_v in enumerate(arr):
        ts = timestamps[i]
        if ts <= 0:
            continue
        val = (_to_float(raw_v) or 0.0) * unit_scale
        b_val = (val * step_sec / 8.0) if kind == "bps" else val
        out.append((ts, b_val))
    return out, True


def _extract_site_series(
    payload: Any,
    spec: MetricSpec,
    default_interval: int = 3600,
) -> Tuple[List[Tuple[int, float, float, float]], bool]:
    """Parse Mist site insights payload into [(ts, total_bytes, tx_bytes, rx_bytes), ...]."""
    if not isinstance(payload, dict):
        return [], False

    # Format A: Columnar Mist response (the exact format of /insights/site/{site_id}/stats!)
    # e.g. {"start": ..., "end": ..., "interval": 3600, "rt": [...], "rx_bytes": [...], "tx_bytes": [...]}
    if spec.rx_key and spec.tx_key:
        rx_arr, rx_rt = _extract_array_from_field(payload, spec.rx_key)
        tx_arr, tx_rt = _extract_array_from_field(payload, spec.tx_key)
        if rx_arr is not None or tx_arr is not None:
            n = max(len(rx_arr or []), len(tx_arr or []))
            if n == 0:
                return [], True
            timestamps, step_sec = _resolve_timestamps(payload, n, default_interval, rx_rt or tx_rt)
            if len(timestamps) < n:
                return [], False
            points: List[Tuple[int, float, float, float]] = []
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

    # Format B: `results` array (plain numbers OR dicts with rx/tx or total)
    if isinstance(payload.get("results"), list):
        results = payload["results"]
        if len(results) == 0:
            return [], True

        non_null = [x for x in results if x is not None]
        if not non_null:
            return [], True

        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in non_null):
            if spec.rx_key and spec.tx_key and not spec.total_key:
                return [], False
            timestamps, step_sec = _resolve_timestamps(payload, len(results), default_interval)
            if len(timestamps) < len(results):
                return [], False
            points = []
            for i, raw_v in enumerate(results):
                ts = timestamps[i]
                if ts <= 0:
                    continue
                val = (_to_float(raw_v) or 0.0) * spec.unit_scale
                tot_b = (val * step_sec / 8.0) if spec.kind == "bps" else val
                points.append((ts, tot_b, 0.0, 0.0))
            return points, True

        if any(isinstance(x, dict) for x in non_null):
            timestamps, step_sec = _resolve_timestamps(payload, len(results), default_interval)
            points = []
            matched_any = False
            rx_aliases = [k for k in (spec.rx_key, "rx_bytes", "rx", "rx_bps", "bytes_rx") if k]
            tx_aliases = [k for k in (spec.tx_key, "tx_bytes", "tx", "tx_bps", "bytes_tx") if k]
            tot_aliases = [k for k in (spec.total_key, "bytes", "total_bytes", "value", "sum", "bps", "bandwidth") if k]

            for i, row in enumerate(results):
                if not isinstance(row, dict):
                    continue
                ts = _norm_epoch_sec(row.get("ts") or row.get("timestamp") or row.get("rt") or row.get("time"))
                if ts <= 0 and i < len(timestamps):
                    ts = timestamps[i]
                if ts <= 0:
                    continue

                rx_k = next((k for k in rx_aliases if k in row), None)
                tx_k = next((k for k in tx_aliases if k in row), None)
                if rx_k or tx_k:
                    matched_any = True
                    rx_val = (_to_float(row.get(rx_k)) if rx_k else 0.0) or 0.0
                    tx_val = (_to_float(row.get(tx_k)) if tx_k else 0.0) or 0.0
                    rx_val *= spec.unit_scale
                    tx_val *= spec.unit_scale
                    if spec.kind == "bps":
                        rx_b = rx_val * step_sec / 8.0
                        tx_b = tx_val * step_sec / 8.0
                    else:
                        rx_b, tx_b = rx_val, tx_val
                    points.append((ts, rx_b + tx_b, tx_b, rx_b))
                    continue

                tot_k = next((k for k in tot_aliases if k in row), None)
                if tot_k:
                    matched_any = True
                    tot_val = (_to_float(row.get(tot_k)) or 0.0) * spec.unit_scale
                    tot_b = (tot_val * step_sec / 8.0) if spec.kind == "bps" else tot_val
                    points.append((ts, tot_b, 0.0, 0.0))
            return points, matched_any

    # Format C: Single metric columnar array
    single_pts, ok = _extract_single_value_series(
        payload,
        metric_key=spec.total_key,
        kind=spec.kind,
        unit_scale=spec.unit_scale,
        default_interval=default_interval,
    )
    if not ok:
        return [], False
    return [(ts, tot_b, 0.0, 0.0) for ts, tot_b in single_pts], True


def _get_json_with_interval_fallback(
    session: requests.Session,
    url: str,
    base_params: Dict[str, str],
    interval_val: str = "3600",
) -> Tuple[Optional[Any], Optional[str]]:
    """GET Mist insights endpoint with `interval=3600`, retrying without `interval` on HTTP 400."""
    params_with_int = dict(base_params)
    if interval_val:
        params_with_int["interval"] = interval_val
    try:
        resp = session.get(url, params=params_with_int, timeout=20)
    except Exception as exc:
        return None, str(exc)

    if resp.status_code == 400 and interval_val:
        try:
            resp = session.get(url, params=base_params, timeout=20)
        except Exception as exc:
            return None, str(exc)

    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}"

    try:
        return resp.json(), None
    except Exception as exc:
        return None, f"Invalid JSON: {exc}"


def _describe_payload_shape(payload: Any) -> str:
    if isinstance(payload, dict):
        keys = list(payload.keys())[:8]
        return f"dict keys={keys}"
    if isinstance(payload, list):
        return f"list len={len(payload)}"
    return type(payload).__name__


def _summarize_raw_probe(session: requests.Session, api_host: str, site_id: str, start_ts: int, end_ts: int) -> str:
    """Safely inspect structural metadata (no secrets/PII) of Mist EU responses when traffic sums to 0."""
    parts: List[str] = []
    probes = [
        ("site_stats", f"{api_host}/api/v1/sites/{site_id}/insights/site/{site_id}/stats", {"start": str(start_ts), "end": str(end_ts), "interval": "3600", "metrics": "rx_bytes,tx_bytes"}),
        ("site_stats_1h", f"{api_host}/api/v1/sites/{site_id}/insights/site/{site_id}/stats", {"duration": "5d", "interval": "1h", "metrics": "rx_bytes,tx_bytes"}),
        ("path_bytes", f"{api_host}/api/v1/sites/{site_id}/insights/bytes", {"start": str(start_ts), "end": str(end_ts), "interval": "1h"}),
        ("path_rx_bytes", f"{api_host}/api/v1/sites/{site_id}/insights/rx_bytes", {"start": str(start_ts), "end": str(end_ts), "interval": "1h"}),
    ]
    for label, url, params in probes:
        try:
            r = session.get(url, params=params, timeout=12)
            if r.status_code != 200:
                parts.append(f"{label}=HTTP {r.status_code}")
                continue
            j = r.json()
            if isinstance(j, dict):
                summary_bits = [f"keys={list(j.keys())[:6]}"]
                for k in ("start", "end", "interval"):
                    if k in j:
                        summary_bits.append(f"{k}={j[k]}")
                for k in ("rt", "rx_bytes", "tx_bytes", "bytes", "results"):
                    v = j.get(k)
                    if isinstance(v, list):
                        non_zero = sum(1 for x in v if isinstance(x, (int, float)) and x > 0)
                        sample = v[:2]
                        summary_bits.append(f"{k}[len={len(v)},nz={non_zero},s={sample}]")
                    elif v is not None:
                        summary_bits.append(f"{k}={type(v).__name__}")
                parts.append(f"{label}({', '.join(summary_bits)})")
            else:
                parts.append(f"{label}={type(j).__name__}")
        except Exception as exc:
            parts.append(f"{label}=err({exc})")
    return " | ".join(parts)


def _query_site_insights(
    session: requests.Session,
    api_host: str,
    site_id: str,
    spec: MetricSpec,
    start_ts: int,
    end_ts: int,
    interval_val: str = "3600",
) -> Tuple[Optional[List[Tuple[int, float, float, float]]], Optional[str]]:
    """Strictly read-only GET query to Mist site insights for one site."""
    base_params = {"start": str(start_ts), "end": str(end_ts)}

    if spec.mode == "site_stats":
        url = f"{api_host}/api/v1/sites/{site_id}/insights/site/{site_id}/stats"
        q_params = dict(base_params)
        q_params["metrics"] = spec.query_metrics
        payload, err = _get_json_with_interval_fallback(session, url, q_params, interval_val)
        if payload is None:
            return None, err
        points, ok = _extract_site_series(payload, spec, default_interval=3600)
        if ok and sum(p[1] for p in points) > 0:
            return points, None
        # Retry with duration=Nd & interval=1h in case Mist prefers relative duration
        dur_days = max(1, int(round((end_ts - start_ts) / 86400.0)))
        dur_params = {"duration": f"{dur_days}d", "interval": "1h", "metrics": spec.query_metrics}
        payload2, _ = _get_json_with_interval_fallback(session, url, dur_params, "")
        if payload2 is not None:
            points2, ok2 = _extract_site_series(payload2, spec, default_interval=3600)
            if ok2 and sum(p[1] for p in points2) > 0:
                return points2, None
        if not ok:
            return None, f"unparsed ({_describe_payload_shape(payload)})"
        return points, None

    if spec.mode == "paired_path" and spec.rx_key and spec.tx_key:
        rx_url = f"{api_host}/api/v1/sites/{site_id}/insights/{spec.rx_key}"
        tx_url = f"{api_host}/api/v1/sites/{site_id}/insights/{spec.tx_key}"
        rx_payload, rx_err = _get_json_with_interval_fallback(session, rx_url, base_params, interval_val)
        if rx_payload is None:
            return None, f"{spec.rx_key}: {rx_err}"
        tx_payload, tx_err = _get_json_with_interval_fallback(session, tx_url, base_params, interval_val)
        if tx_payload is None:
            return None, f"{spec.tx_key}: {tx_err}"

        rx_pts, rx_ok = _extract_single_value_series(rx_payload, spec.rx_key, spec.kind, spec.unit_scale)
        tx_pts, tx_ok = _extract_single_value_series(tx_payload, spec.tx_key, spec.kind, spec.unit_scale)
        if not (rx_ok and tx_ok):
            return None, f"unparsed ({_describe_payload_shape(rx_payload)})"

        merged: Dict[int, List[float]] = {}
        for ts, rx_b in rx_pts:
            merged.setdefault(ts, [0.0, 0.0])[0] += rx_b
        for ts, tx_b in tx_pts:
            merged.setdefault(ts, [0.0, 0.0])[1] += tx_b
        out = [(ts, vals[0] + vals[1], vals[1], vals[0]) for ts, vals in sorted(merged.items())]
        return out, None

    metric_name = spec.total_key or spec.query_metrics
    url = f"{api_host}/api/v1/sites/{site_id}/insights/{metric_name}"
    payload, err = _get_json_with_interval_fallback(session, url, base_params, interval_val)
    if payload is None:
        return None, err

    points, ok = _extract_site_series(payload, spec, default_interval=3600)
    if not ok:
        return None, f"unparsed ({_describe_payload_shape(payload)})"
    return points, None


def _load_sites(
    session: requests.Session,
    api_host: str,
    org_id: str,
    site_name_map: Optional[Dict[str, str]] = None,
    prioritized_site_ids: Optional[List[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    sites = dict(site_name_map or {})
    live_priority: List[str] = list(prioritized_site_ids or [])

    if not sites or not live_priority:
        # Try /orgs/{org_id}/stats/sites first: gives site names AND live client/AP counts so we probe active sites first!
        try:
            resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/stats/sites", params={"limit": 1000}, timeout=20)
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
                        num_clients = int(_to_float(s.get("num_clients")) or 0)
                        num_aps = int(_to_float(s.get("num_aps")) or 0)
                        scored.append((num_clients, num_aps, sid))
                    if not live_priority and scored:
                        scored.sort(key=lambda t: (-t[0], -t[1], sites.get(t[2], "").lower()))
                        live_priority = [t[2] for t in scored]
        except Exception:
            pass

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
    for sid in live_priority:
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

    # Probe busiest active site(s) to verify the exact working Mist traffic endpoint & metric
    probe_sites = target_site_ids[:5]
    best_zero_spec: Optional[MetricSpec] = None
    best_zero_prefetched: Dict[str, List[Tuple[int, float, float, float]]] = {}
    probe_errors: List[str] = []

    for spec in candidates:
        spec_hits: Dict[str, List[Tuple[int, float, float, float]]] = {}
        total_nonzero = 0.0
        any_ok = False
        last_err: Optional[str] = None
        for sid in probe_sites:
            pts, err = _query_site_insights(session, api_host, sid, spec, start_ts, end_ts, "3600")
            if pts is not None:
                any_ok = True
                spec_hits[sid] = pts
                total_nonzero += sum(p[1] for p in pts)
                if total_nonzero > 0:
                    break
            elif err:
                last_err = err
        if any_ok and total_nonzero > 0:
            chosen_spec = spec
            prefetched = spec_hits
            break
        if any_ok and best_zero_spec is None:
            best_zero_spec = spec
            best_zero_prefetched = spec_hits
        elif last_err and len(probe_errors) < 5:
            probe_errors.append(f"{spec.query_metrics}[{spec.mode}]: {last_err}")

    if chosen_spec is None and best_zero_spec is not None:
        chosen_spec = best_zero_spec
        prefetched = best_zero_prefetched

    if chosen_spec is None:
        diag = "; ".join(probe_errors) if probe_errors else "no candidates returned data"
        warnings.append(
            f"Mist Insights did not return a recognized site traffic metric ({diag})."
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
                pool.submit(_query_site_insights, session, api_host, sid, chosen_spec, start_ts, end_ts, "3600"): sid
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
    has_rx_tx_split = bool(grand_rx_bytes > 0 or grand_tx_bytes > 0)
    avg_mbps_overall = (grand_total_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_tx_mbps_overall = (grand_tx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6
    avg_rx_mbps_overall = (grand_rx_bytes * 8.0) / max(1, total_elapsed_sec) / 1e6

    if grand_total_bytes <= 0 and target_site_ids:
        probe_diag = _summarize_raw_probe(session, api_host, target_site_ids[0], start_ts, end_ts)
        if probe_diag:
            warnings.append(f"Mist probe: {probe_diag}")

    return {
        "days": days,
        "duration_label": DAY_LABELS.get(days, f"Last {days} Days"),
        "site_id": selected_site,
        "site_name": selected_site_name,
        "timezone": DISPLAY_TIMEZONE,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "metric_used": f"{chosen_spec.query_metrics} ({chosen_spec.mode})",
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
