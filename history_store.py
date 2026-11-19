from calendar import monthrange
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

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
_db_lock = threading.Lock()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_history_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with _db_lock:
        conn = _connect(db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wifi_history (
                    ts INTEGER PRIMARY KEY,
                    total_users INTEGER NOT NULL,
                    eduroam_users INTEGER NOT NULL,
                    uop_visitor_users INTEGER NOT NULL,
                    uop_connect_users INTEGER NOT NULL,
                    other_users INTEGER NOT NULL,
                    ssids_json TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()


def record_snapshot(
    db_path: Path,
    snapshot: Dict[str, Any],
    ts: Optional[int] = None,
    min_interval_sec: int = 55,
) -> bool:
    """Persist a live Wi-Fi user snapshot to SQLite if at least min_interval_sec has elapsed."""
    if not isinstance(snapshot, dict):
        return False
    summary = snapshot.get("summary")
    if not isinstance(summary, dict):
        return False

    sample_ts = int(ts if ts is not None else time.time())
    total_users = int(summary.get("total_wireless_users") or 0)
    eduroam_users = int(summary.get("eduroam_users") or 0)
    uop_visitor_users = int(summary.get("uop_visitor_users") or 0)
    uop_connect_users = int(summary.get("uop_connect_users") or 0)
    other_users = int(
        summary.get("other_wireless_users")
        if summary.get("other_wireless_users") is not None
        else max(0, total_users - eduroam_users - uop_visitor_users - uop_connect_users)
    )

    ssids_map: Dict[str, int] = {}
    for entry in snapshot.get("ssids") or []:
        if isinstance(entry, dict) and entry.get("name"):
            ssids_map[str(entry["name"])] = int(entry.get("count") or 0)
    ssids_json = json.dumps(ssids_map, separators=(",", ":"), sort_keys=True)

    with _db_lock:
        conn = _connect(db_path)
        try:
            if min_interval_sec > 0:
                row = conn.execute("SELECT MAX(ts) AS max_ts FROM wifi_history").fetchone()
                if row and row["max_ts"] is not None:
                    if sample_ts - int(row["max_ts"]) < min_interval_sec and sample_ts >= int(row["max_ts"]):
                        return False
            conn.execute(
                """
                INSERT OR REPLACE INTO wifi_history
                    (ts, total_users, eduroam_users, uop_visitor_users, uop_connect_users, other_users, ssids_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample_ts,
                    total_users,
                    eduroam_users,
                    uop_visitor_users,
                    uop_connect_users,
                    other_users,
                    ssids_json,
                ),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def _fmt_peak_time(ts: Optional[int]) -> str:
    if not ts:
        return ""
    dt = datetime.fromtimestamp(ts, tz=DISPLAY_TZ)
    return dt.strftime("%a %d %b %Y, %H:%M")


def _fmt_peak_short(ts: Optional[int]) -> str:
    if not ts:
        return ""
    dt = datetime.fromtimestamp(ts, tz=DISPLAY_TZ)
    return dt.strftime("%a %d %b, %H:%M")


def _resolve_window(
    range_type: str,
    anchor: Optional[str],
    now_dt: datetime,
    first_ts: Optional[int],
) -> Tuple[int, int, str, Optional[str], Optional[str], Optional[str]]:
    """Return (start_ts, end_ts, period_label, prev_anchor, next_anchor, normalized_anchor)."""
    now_ts = int(now_dt.timestamp())
    clean_anchor = (anchor or "").strip() or None

    if range_type == "day":
        if clean_anchor:
            try:
                day_dt = datetime.strptime(clean_anchor, "%Y-%m-%d").replace(tzinfo=DISPLAY_TZ)
            except ValueError:
                day_dt = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            start_dt = day_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = start_dt + timedelta(days=1) - timedelta(seconds=1)
            prev_anchor = (start_dt - timedelta(days=1)).strftime("%Y-%m-%d")
            next_day = start_dt + timedelta(days=1)
            today_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            next_anchor = next_day.strftime("%Y-%m-%d") if next_day <= today_start else None
            return (
                int(start_dt.timestamp()),
                int(end_dt.timestamp()),
                start_dt.strftime("%a %d %b %Y"),
                prev_anchor,
                next_anchor,
                start_dt.strftime("%Y-%m-%d"),
            )
        start_dt = now_dt - timedelta(hours=24)
        prev_day = (now_dt.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)).strftime("%Y-%m-%d")
        return int(start_dt.timestamp()), now_ts, "Last 24 Hours", prev_day, None, None

    if range_type == "week":
        if clean_anchor:
            try:
                week_start = datetime.strptime(clean_anchor, "%Y-%m-%d").replace(tzinfo=DISPLAY_TZ)
            except ValueError:
                week_start = (now_dt - timedelta(days=now_dt.weekday())).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
            start_dt = week_start.replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = start_dt + timedelta(days=7) - timedelta(seconds=1)
            prev_anchor = (start_dt - timedelta(days=7)).strftime("%Y-%m-%d")
            next_start = start_dt + timedelta(days=7)
            next_anchor = next_start.strftime("%Y-%m-%d") if next_start <= now_dt else None
            label = f"{start_dt.strftime('%d %b')} – {(start_dt + timedelta(days=6)).strftime('%d %b %Y')}"
            return (
                int(start_dt.timestamp()),
                int(end_dt.timestamp()),
                label,
                prev_anchor,
                next_anchor,
                start_dt.strftime("%Y-%m-%d"),
            )
        start_dt = now_dt - timedelta(days=7)
        prev_week_start = (now_dt - timedelta(days=14)).strftime("%Y-%m-%d")
        return int(start_dt.timestamp()), now_ts, "Last 7 Days", prev_week_start, None, None

    if range_type == "month":
        if clean_anchor:
            try:
                month_dt = datetime.strptime(clean_anchor, "%Y-%m").replace(tzinfo=DISPLAY_TZ)
            except ValueError:
                month_dt = now_dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            y, m = month_dt.year, month_dt.month
            last_day = monthrange(y, m)[1]
            start_dt = datetime(y, m, 1, 0, 0, 0, tzinfo=DISPLAY_TZ)
            end_dt = datetime(y, m, last_day, 23, 59, 59, tzinfo=DISPLAY_TZ)
            prev_y, prev_m = (y - 1, 12) if m == 1 else (y, m - 1)
            next_y, next_m = (y + 1, 1) if m == 12 else (y, m + 1)
            next_start = datetime(next_y, next_m, 1, 0, 0, 0, tzinfo=DISPLAY_TZ)
            prev_anchor = f"{prev_y:04d}-{prev_m:02d}"
            next_anchor = f"{next_y:04d}-{next_m:02d}" if next_start <= now_dt else None
            return (
                int(start_dt.timestamp()),
                int(end_dt.timestamp()),
                start_dt.strftime("%B %Y"),
                prev_anchor,
                next_anchor,
                f"{y:04d}-{m:02d}",
            )
        start_dt = now_dt - timedelta(days=30)
        prev_m_y, prev_m = (now_dt.year - 1, 12) if now_dt.month == 1 else (now_dt.year, now_dt.month - 1)
        return int(start_dt.timestamp()), now_ts, "Last 30 Days", f"{prev_m_y:04d}-{prev_m:02d}", None, None

    if range_type == "year":
        if clean_anchor:
            try:
                y = int(clean_anchor[:4])
                if y < 2000 or y > 2100:
                    y = now_dt.year
            except ValueError:
                y = now_dt.year
            start_dt = datetime(y, 1, 1, 0, 0, 0, tzinfo=DISPLAY_TZ)
            end_dt = datetime(y, 12, 31, 23, 59, 59, tzinfo=DISPLAY_TZ)
            prev_anchor = str(y - 1)
            next_anchor = str(y + 1) if y + 1 <= now_dt.year else None
            return (
                int(start_dt.timestamp()),
                int(end_dt.timestamp()),
                str(y),
                prev_anchor,
                next_anchor,
                str(y),
            )
        start_dt = now_dt - timedelta(days=365)
        return int(start_dt.timestamp()), now_ts, "Last 12 Months", str(now_dt.year - 1), None, None

    # "all" — all recorded history
    start_ts = first_ts if first_ts is not None else int((now_dt - timedelta(days=1)).timestamp())
    return start_ts, now_ts, "All Time", None, None, None


def _bucket_descriptor(
    dt: datetime,
    bucket_mode: str,
) -> Tuple[str, str, str, Optional[Dict[str, str]]]:
    """Return (bucket_key, short_label, full_label, drill_target)."""
    if bucket_mode == "15min":
        q_min = (dt.minute // 15) * 15
        bdt = dt.replace(minute=q_min, second=0, microsecond=0)
        key = bdt.strftime("%Y-%m-%dT%H:%M")
        return key, bdt.strftime("%H:%M"), bdt.strftime("%a %d %b %Y, %H:%M"), None

    if bucket_mode == "hour":
        bdt = dt.replace(minute=0, second=0, microsecond=0)
        key = bdt.strftime("%Y-%m-%dT%H:00")
        day_anchor = bdt.strftime("%Y-%m-%d")
        return (
            key,
            bdt.strftime("%a %H:%M"),
            bdt.strftime("%a %d %b %Y, %H:00"),
            {"range": "day", "anchor": day_anchor, "label": bdt.strftime("%a %d %b %Y")},
        )

    if bucket_mode == "day_to_month":
        bdt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        key = bdt.strftime("%Y-%m-%d")
        return (
            key,
            bdt.strftime("%d %b"),
            bdt.strftime("%a %d %b %Y"),
            {"range": "month", "anchor": bdt.strftime("%Y-%m"), "label": bdt.strftime("%B %Y")},
        )

    if bucket_mode == "month":
        bdt = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        key = bdt.strftime("%Y-%m")
        return (
            key,
            bdt.strftime("%b %Y"),
            bdt.strftime("%B %Y"),
            {"range": "month", "anchor": key, "label": bdt.strftime("%B %Y")},
        )

    # Default: daily peak drilling directly into day view
    bdt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    key = bdt.strftime("%Y-%m-%d")
    return (
        key,
        bdt.strftime("%d %b"),
        bdt.strftime("%a %d %b %Y"),
        {"range": "day", "anchor": key, "label": bdt.strftime("%a %d %b %Y")},
    )


def _selected_ssid_value(
    ssid_filter: str,
    total: int,
    eduroam: int,
    visitor: int,
    connect: int,
    other: int,
    ssids_dict: Dict[str, int],
) -> int:
    if ssid_filter in ("all", "total"):
        return total
    if ssid_filter == "eduroam":
        return eduroam
    if ssid_filter == "uop_visitor":
        return visitor
    if ssid_filter == "uop_connect":
        return connect
    if ssid_filter == "other":
        return other
    if ssid_filter.startswith("ssid:"):
        target = ssid_filter[5:]
        if target in ssids_dict:
            return int(ssids_dict[target])
        target_low = target.lower()
        for k, v in ssids_dict.items():
            if k.lower() == target_low:
                return int(v)
        return 0
    return total


def _ssid_display_label(ssid_filter: str) -> str:
    labels = {
        "all": "Total Wi-Fi (All SSIDs)",
        "total": "Total Wi-Fi",
        "eduroam": "eduroam",
        "uop_visitor": "UoP Visitor",
        "uop_connect": "UoP Connect",
        "other": "Other SSIDs",
    }
    if ssid_filter in labels:
        return labels[ssid_filter]
    if ssid_filter.startswith("ssid:"):
        return ssid_filter[5:]
    return "Total Wi-Fi"


def query_history(
    db_path: Path,
    range_type: str = "day",
    anchor: Optional[str] = None,
    ssid: str = "all",
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Query recorded Wi-Fi concurrent peak history with period bucketing and drill-down metadata."""
    valid_ranges = ("day", "week", "month", "year", "all")
    norm_range = range_type if range_type in valid_ranges else "day"
    norm_ssid = (ssid or "all").strip() or "all"
    now_dt = datetime.fromtimestamp(now_ts if now_ts is not None else time.time(), tz=DISPLAY_TZ)

    with _db_lock:
        conn = _connect(db_path)
        try:
            meta_row = conn.execute(
                "SELECT MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS total_samples FROM wifi_history"
            ).fetchone()
            first_ts = int(meta_row["first_ts"]) if meta_row and meta_row["first_ts"] is not None else None
            last_ts = int(meta_row["last_ts"]) if meta_row and meta_row["last_ts"] is not None else None
            total_db_samples = int(meta_row["total_samples"]) if meta_row else 0

            start_ts, end_ts, period_label, prev_anchor, next_anchor, norm_anchor = _resolve_window(
                norm_range, anchor, now_dt, first_ts
            )

            rows = conn.execute(
                """
                SELECT ts, total_users, eduroam_users, uop_visitor_users, uop_connect_users, other_users, ssids_json
                FROM wifi_history
                WHERE ts >= ? AND ts <= ?
                ORDER BY ts ASC
                """,
                (start_ts, end_ts),
            ).fetchall()

            # Discover available SSIDs from recent samples (up to last 500 rows for speed)
            ssid_rows = conn.execute(
                "SELECT ssids_json FROM wifi_history ORDER BY ts DESC LIMIT 500"
            ).fetchall()
        finally:
            conn.close()

    ssid_max_map: Dict[str, int] = {}
    for sr in ssid_rows:
        try:
            parsed = json.loads(sr["ssids_json"] or "{}")
            if isinstance(parsed, dict):
                for name, cnt in parsed.items():
                    cnt_i = int(cnt or 0)
                    if cnt_i > ssid_max_map.get(name, -1):
                        ssid_max_map[name] = cnt_i
        except Exception:
            pass

    available_ssids = [
        name for name, _ in sorted(ssid_max_map.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    ]

    # Determine bucket granularity
    span_days = max(0.0, (end_ts - start_ts) / 86400.0)
    if norm_range == "day":
        bucket_mode = "15min"
        granularity_label = "15-minute concurrent peaks"
    elif norm_range == "week":
        bucket_mode = "hour"
        granularity_label = "Hourly concurrent peaks"
    elif norm_range == "month":
        bucket_mode = "day"
        granularity_label = "Daily concurrent peaks"
    elif norm_range == "year":
        bucket_mode = "day_to_month"
        granularity_label = "Daily concurrent peaks"
    else:
        if span_days > 400:
            bucket_mode = "month"
            granularity_label = "Monthly concurrent peaks"
        else:
            bucket_mode = "day"
            granularity_label = "Daily concurrent peaks"

    buckets: Dict[str, Dict[str, Any]] = {}
    bucket_order: List[str] = []

    def _empty_peak() -> Dict[str, Any]:
        return {"value": 0, "ts": None, "time_label": "", "short_time": ""}

    period_peaks = {
        "total": _empty_peak(),
        "eduroam": _empty_peak(),
        "uop_visitor": _empty_peak(),
        "uop_connect": _empty_peak(),
        "other": _empty_peak(),
        "selected": _empty_peak(),
    }

    selected_sum = 0
    sample_count = 0

    for row in rows:
        ts = int(row["ts"])
        total = int(row["total_users"])
        eduroam = int(row["eduroam_users"])
        visitor = int(row["uop_visitor_users"])
        connect = int(row["uop_connect_users"])
        other = int(row["other_users"])
        try:
            ssids_dict = json.loads(row["ssids_json"] or "{}")
            if not isinstance(ssids_dict, dict):
                ssids_dict = {}
        except Exception:
            ssids_dict = {}

        selected = _selected_ssid_value(norm_ssid, total, eduroam, visitor, connect, other, ssids_dict)
        selected_sum += selected
        sample_count += 1

        # Update period-wide peaks
        series_vals = {
            "total": total,
            "eduroam": eduroam,
            "uop_visitor": visitor,
            "uop_connect": connect,
            "other": other,
            "selected": selected,
        }
        for s_key, s_val in series_vals.items():
            if period_peaks[s_key]["ts"] is None or s_val > period_peaks[s_key]["value"]:
                period_peaks[s_key] = {
                    "value": s_val,
                    "ts": ts,
                    "time_label": _fmt_peak_time(ts),
                    "short_time": _fmt_peak_short(ts),
                }

        dt = datetime.fromtimestamp(ts, tz=DISPLAY_TZ)
        b_key, short_label, full_label, drill_target = _bucket_descriptor(dt, bucket_mode)
        if b_key not in buckets:
            bucket_order.append(b_key)
            buckets[b_key] = {
                "key": b_key,
                "label": short_label,
                "full_label": full_label,
                "total": total,
                "total_peak_ts": ts,
                "eduroam": eduroam,
                "eduroam_peak_ts": ts,
                "uop_visitor": visitor,
                "uop_visitor_peak_ts": ts,
                "uop_connect": connect,
                "uop_connect_peak_ts": ts,
                "other": other,
                "other_peak_ts": ts,
                "selected": selected,
                "selected_peak_ts": ts,
                "samples": 1,
                "drill_target": drill_target,
            }
        else:
            b = buckets[b_key]
            b["samples"] += 1
            for s_key, s_val in series_vals.items():
                if s_val > b[s_key]:
                    b[s_key] = s_val
                    b[f"{s_key}_peak_ts"] = ts

    points: List[Dict[str, Any]] = []
    for b_key in bucket_order:
        b = buckets[b_key]
        b["total_peak_time"] = _fmt_peak_short(b["total_peak_ts"])
        b["eduroam_peak_time"] = _fmt_peak_short(b["eduroam_peak_ts"])
        b["uop_visitor_peak_time"] = _fmt_peak_short(b["uop_visitor_peak_ts"])
        b["uop_connect_peak_time"] = _fmt_peak_short(b["uop_connect_peak_ts"])
        b["selected_peak_time"] = _fmt_peak_short(b["selected_peak_ts"])
        points.append(b)

    return {
        "range": norm_range,
        "anchor": norm_anchor,
        "period_label": period_label,
        "granularity": bucket_mode,
        "granularity_label": granularity_label,
        "timezone": DISPLAY_TIMEZONE,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "prev_anchor": prev_anchor,
        "next_anchor": next_anchor,
        "ssid": norm_ssid,
        "ssid_label": _ssid_display_label(norm_ssid),
        "available_ssids": available_ssids,
        "sample_count": sample_count,
        "total_db_samples": total_db_samples,
        "first_sample_ts": first_ts,
        "first_sample_label": _fmt_peak_time(first_ts) if first_ts else None,
        "last_sample_ts": last_ts,
        "last_sample_label": _fmt_peak_time(last_ts) if last_ts else None,
        "avg_selected": round(selected_sum / sample_count) if sample_count > 0 else 0,
        "peaks": period_peaks,
        "points": points,
    }
