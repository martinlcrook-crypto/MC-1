from concurrent.futures import ThreadPoolExecutor
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import requests

from traffic_stats import MistRateLimitError

MAC_CLEAN_RE = re.compile(r"[^0-9a-fA-F]")
MAC_IN_TEXT_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|\b[0-9a-fA-F]{12}\b")
PORT_IN_TEXT_RE = re.compile(r"\b(?:ge|xe|mge|et|ae)-\d+/\d+/\d+(?:\.\d+)?\b", re.IGNORECASE)


def normalize_mac(raw: Any) -> str:
    cleaned = MAC_CLEAN_RE.sub("", str(raw or "")).lower()
    return cleaned if len(cleaned) == 12 else ""


def format_mac(raw: Any) -> str:
    norm = normalize_mac(raw)
    if not norm:
        return str(raw or "").strip()
    return ":".join(norm[i : i + 2] for i in range(0, 12, 2))


def _mist_search_get(
    session: requests.Session,
    api_host: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    max_pages: int = 3,
) -> List[Dict[str, Any]]:
    """Strictly read-only GET helper for Mist */search endpoints supporting search_after pagination."""
    results: List[Dict[str, Any]] = []
    req_params = dict(params or {})
    req_params.setdefault("limit", 1000)

    for _ in range(max_pages):
        resp = session.get(f"{api_host}{path}", params=req_params, timeout=20)
        if resp.status_code == 429:
            raise MistRateLimitError(
                "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
            )
        if resp.status_code in (403, 404):
            return results
        resp.raise_for_status()
        payload = resp.json()

        if isinstance(payload, list):
            results.extend(x for x in payload if isinstance(x, dict))
            break
        if not isinstance(payload, dict):
            break

        batch = payload.get("results")
        if isinstance(batch, list):
            results.extend(x for x in batch if isinstance(x, dict))
        else:
            break

        next_url = payload.get("next")
        if not next_url or not batch:
            break
        parsed = urlparse(str(next_url))
        qs = parse_qs(parsed.query)
        search_after = (qs.get("search_after") or [None])[0]
        if not search_after:
            break
        req_params["search_after"] = search_after

    return results


def extract_nac_port_profiles(
    templates: List[Dict[str, Any]],
) -> Tuple[Set[str], Dict[int, List[str]], Dict[str, Dict[str, Any]]]:
    """
    Inspect Mist org network templates to discover:
    - nac_profile_names: port_usages names that use 802.1X / MAC auth
    - reject_vlan_to_names: mapping of numeric server_reject_network VLAN ID -> [network/profile labels]
    - profile_meta: metadata per port_usage name (port_auth, server_reject_network, server_reject_vlan_id)
    """
    nac_profile_names: Set[str] = set()
    reject_vlan_to_names: Dict[int, List[str]] = {}
    profile_meta: Dict[str, Dict[str, Any]] = {}

    for tpl in templates or []:
        if not isinstance(tpl, dict):
            continue
        networks = tpl.get("networks") if isinstance(tpl.get("networks"), dict) else {}
        vlan_name_to_id: Dict[str, int] = {}
        for net_name, net_cfg in networks.items():
            if not isinstance(net_cfg, dict):
                continue
            vid = net_cfg.get("vlan_id")
            try:
                vid_int = int(str(vid).strip())
                if vid_int > 0:
                    vlan_name_to_id[str(net_name)] = vid_int
                    vlan_name_to_id[str(net_name).lower()] = vid_int
            except (TypeError, ValueError):
                pass

        port_usages = tpl.get("port_usages") if isinstance(tpl.get("port_usages"), dict) else {}
        for usage_name, cfg in port_usages.items():
            if not isinstance(cfg, dict):
                continue
            port_auth = str(cfg.get("port_auth") or "").strip().lower()
            enable_mac_auth = bool(cfg.get("enable_mac_auth"))
            reject_net = str(cfg.get("server_reject_network") or "").strip()
            is_nac = (
                port_auth == "dot1x"
                or enable_mac_auth
                or bool(reject_net)
                or "nac" in usage_name.lower()
                or "dot1x" in usage_name.lower()
            )
            if not is_nac:
                continue

            nac_profile_names.add(usage_name)
            reject_vid: Optional[int] = None
            if reject_net:
                reject_vid = vlan_name_to_id.get(reject_net) or vlan_name_to_id.get(reject_net.lower())
                if reject_vid is None:
                    try:
                        parsed_vid = int(reject_net)
                        if parsed_vid > 0:
                            reject_vid = parsed_vid
                    except ValueError:
                        reject_vid = None

            if reject_vid is not None:
                entry_label = f"{reject_net} (VLAN {reject_vid})"
                labels = reject_vlan_to_names.setdefault(reject_vid, [])
                if entry_label not in labels:
                    labels.append(entry_label)

            profile_meta[usage_name] = {
                "name": usage_name,
                "port_auth": port_auth or ("mac_auth" if enable_mac_auth else "nac"),
                "enable_mac_auth": enable_mac_auth,
                "server_reject_network": reject_net or None,
                "server_reject_vlan_id": reject_vid,
            }

    return nac_profile_names, reject_vlan_to_names, profile_meta


def _extract_wired_port_info(item: Dict[str, Any]) -> Tuple[str, str, Optional[int], str, str, str]:
    """Extract (switch_mac, port_id, vlan_id, auth_state, auth_method, port_usage) from wired client record."""
    device_mac = normalize_mac(item.get("device_mac"))
    port_id = str(item.get("port_id") or "").strip()
    vlan_raw = item.get("vlan")
    auth_state = str(item.get("auth_state") or "").strip()
    auth_method = str(item.get("auth_method") or "").strip()
    port_usage = str(item.get("port_usage") or "").strip()

    dmp = item.get("device_mac_port")
    if isinstance(dmp, list) and dmp:
        latest = dmp[0] if isinstance(dmp[0], dict) else {}
        if not device_mac:
            device_mac = normalize_mac(latest.get("device_mac"))
        if not port_id:
            port_id = str(latest.get("port_id") or "").strip()
        if vlan_raw is None:
            vlan_raw = latest.get("vlan")
        if not auth_state:
            auth_state = str(latest.get("auth_state") or "").strip()
        if not auth_method:
            auth_method = str(latest.get("auth_method") or "").strip()
        if not port_usage:
            port_usage = str(latest.get("port_usage") or "").strip()

    vlan_id: Optional[int] = None
    if isinstance(vlan_raw, list) and vlan_raw:
        vlan_raw = vlan_raw[0]
    try:
        if vlan_raw is not None and str(vlan_raw).strip() != "":
            vlan_id = int(str(vlan_raw).strip())
    except (TypeError, ValueError):
        vlan_id = None

    return device_mac, port_id, vlan_id, auth_state, auth_method, port_usage


def _is_reject_auth_state(auth_state: str) -> bool:
    low = (auth_state or "").strip().lower()
    return any(tok in low for tok in ("reject", "denied", "deny", "fail"))


def _first_str(val: Any) -> str:
    if isinstance(val, list):
        for item in val:
            s = str(item or "").strip()
            if s:
                return s
        return ""
    return str(val or "").strip()


def _merge_record(
    records: Dict[Tuple[str, str, str], Dict[str, Any]],
    rec: Dict[str, Any],
) -> None:
    key = (
        normalize_mac(rec.get("mac")) or str(rec.get("mac") or "").lower(),
        normalize_mac(rec.get("switch_mac")),
        str(rec.get("port_id") or "").lower(),
    )
    existing = records.get(key)
    if existing is None:
        records[key] = rec
        return

    # Merge richest fields, preferring the newer timestamp and preserving known port_usage/reason/hostname
    if (rec.get("timestamp") or 0) >= (existing.get("timestamp") or 0):
        existing["timestamp"] = rec.get("timestamp") or existing.get("timestamp")
        if rec.get("reject_type") and existing.get("reject_type") == "Switch Event":
            existing["reject_type"] = rec["reject_type"]
    for field in (
        "hostname",
        "ip",
        "manufacture",
        "username",
        "switch_name",
        "site_name",
        "site_id",
        "port_usage",
        "auth_state",
        "auth_method",
        "nacrule_name",
        "reason",
        "vlan_name",
    ):
        if not existing.get(field) and rec.get(field):
            existing[field] = rec[field]
    if existing.get("vlan") is None and rec.get("vlan") is not None:
        existing["vlan"] = rec["vlan"]
    sources = existing.setdefault("sources", [])
    for src in rec.get("sources") or []:
        if src not in sources:
            sources.append(src)


def collect_nac_server_rejects(
    session: requests.Session,
    api_host: str,
    org_id: str,
    duration: str = "24h",
    site_name_map: Optional[Dict[str, str]] = None,
    switch_info_map: Optional[Dict[str, Dict[str, Any]]] = None,
    network_templates: Optional[List[Dict[str, Any]]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Strictly read-only collector for devices that received Server Reject on a NAC port profile
    within the last 24 hours.
    Combines:
      1. Org Switch Templates (networktemplates) to identify NAC port profiles & server_reject_network VLANs
      2. Wired Client Search (auth_state=server_reject and configured server_reject_network VLANs)
      3. Mist Access Assurance Wired Denies (nac_clients/search?status=denied&type=wired)
      4. Switch 802.1X Server-Reject Events (devices/events/search?device_type=switch&text=reject)
      5. Switch Port Stats enrichment (stats/ports/search) to resolve the exact NAC port profile (port_usage)
    """
    end_ts = int(now_ts if now_ts is not None else time.time())
    cutoff_ts = end_ts - 86400
    mist_duration = "1d"
    display_duration = "24h"
    time_window_params = {"start": cutoff_ts, "end": end_ts, "duration": mist_duration}

    warnings: List[str] = []
    sites_by_id = dict(site_name_map or {})
    switches_by_mac = dict(switch_info_map or {})

    def safe_call(label: str, fn: Callable[[], Any], default: Any) -> Any:
        try:
            return fn()
        except MistRateLimitError:
            raise
        except Exception as exc:
            warnings.append(f"{label}: {exc}")
            return default

    # Phase 1: Sites/Switches (if not supplied), Switch Templates, Wired Server-Rejects, NAC Denies, Switch Events
    def fetch_sites():
        if sites_by_id:
            return None
        resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/sites", timeout=20)
        if resp.status_code == 429:
            raise MistRateLimitError(
                "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
            )
        resp.raise_for_status()
        return resp.json()

    def fetch_switches():
        if switches_by_mac:
            return None
        resp = session.get(
            f"{api_host}/api/v1/orgs/{org_id}/stats/devices",
            params={"type": "switch", "status": "all", "limit": 1000},
            timeout=20,
        )
        if resp.status_code == 429:
            raise MistRateLimitError(
                "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
            )
        resp.raise_for_status()
        return resp.json()

    def fetch_templates():
        if network_templates is not None:
            return network_templates
        resp = session.get(f"{api_host}/api/v1/orgs/{org_id}/networktemplates", timeout=20)
        if resp.status_code == 429:
            raise MistRateLimitError(
                "Juniper Mist API rate limit reached (HTTP 429). Please wait a few minutes and try again."
            )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []

    with ThreadPoolExecutor(max_workers=6) as pool:
        f_sites = pool.submit(safe_call, "sites", fetch_sites, [])
        f_switches = pool.submit(safe_call, "switches", fetch_switches, [])
        f_templates = pool.submit(safe_call, "networktemplates", fetch_templates, [])
        f_wired_sr = pool.submit(
            safe_call,
            "wired_clients(server_reject)",
            lambda: _mist_search_get(
                session,
                api_host,
                f"/api/v1/orgs/{org_id}/wired_clients/search",
                {"auth_state": "server_reject", **time_window_params, "limit": 1000},
            ),
            [],
        )
        f_nac_denied = pool.submit(
            safe_call,
            "nac_clients(denied)",
            lambda: _mist_search_get(
                session,
                api_host,
                f"/api/v1/orgs/{org_id}/nac_clients/search",
                {"status": "denied", "type": "wired", **time_window_params, "limit": 1000},
            ),
            [],
        )
        f_sw_events = pool.submit(
            safe_call,
            "switch_events(reject)",
            lambda: _mist_search_get(
                session,
                api_host,
                f"/api/v1/orgs/{org_id}/devices/events/search",
                {"device_type": "switch", "text": "reject", **time_window_params, "limit": 1000},
                max_pages=2,
            ),
            [],
        )

        raw_sites = f_sites.result()
        raw_switches = f_switches.result()
        templates = f_templates.result()
        wired_sr_list = f_wired_sr.result()
        nac_denied_list = f_nac_denied.result()
        sw_events_list = f_sw_events.result()

    if isinstance(raw_sites, list):
        for s in raw_sites:
            if isinstance(s, dict) and s.get("id"):
                sites_by_id[str(s["id"])] = str(s.get("name") or s["id"])

    if isinstance(raw_switches, list):
        for sw in raw_switches:
            if not isinstance(sw, dict):
                continue
            smac = normalize_mac(sw.get("mac"))
            if smac:
                switches_by_mac[smac] = {
                    "name": str(sw.get("name") or format_mac(smac)),
                    "site_id": str(sw.get("site_id") or ""),
                    "model": str(sw.get("model") or ""),
                    "ip": str(sw.get("ip") or ""),
                }

    nac_profile_names, reject_vlan_to_names, profile_meta = extract_nac_port_profiles(templates)

    # Phase 2: If templates define explicit server_reject_network VLAN IDs, also query wired clients on those VLANs
    wired_reject_vlan_list: List[Dict[str, Any]] = []
    if reject_vlan_to_names:
        vlan_csv = ",".join(str(v) for v in sorted(reject_vlan_to_names.keys()))
        wired_reject_vlan_list = safe_call(
            "wired_clients(server_reject_vlan)",
            lambda: _mist_search_get(
                session,
                api_host,
                f"/api/v1/orgs/{org_id}/wired_clients/search",
                {"vlan": vlan_csv, **time_window_params, "limit": 1000},
            ),
            [],
        )

    records: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def switch_label(smac: str, site_id: str) -> Tuple[str, str]:
        sw = switches_by_mac.get(smac) or {}
        resolved_site_id = site_id or sw.get("site_id") or ""
        sname = sites_by_id.get(resolved_site_id) or (resolved_site_id or "Unknown Site")
        sw_name = sw.get("name") or (format_mac(smac) if smac else "Unknown Switch")
        return sw_name, sname

    # Process Wired Clients matching auth_state=server_reject
    for item in wired_sr_list:
        cmac = normalize_mac(item.get("mac"))
        if not cmac:
            continue
        smac, port_id, vlan_id, auth_state, auth_method, port_usage = _extract_wired_port_info(item)
        site_id = str(item.get("site_id") or "")
        sw_name, site_name = switch_label(smac, site_id)
        vlan_name = ", ".join(reject_vlan_to_names.get(vlan_id, [])) if vlan_id is not None else ""
        _merge_record(
            records,
            {
                "mac": format_mac(cmac),
                "hostname": _first_str(item.get("hostname")) or _first_str(item.get("dhcp_hostname")),
                "ip": _first_str(item.get("ip")),
                "manufacture": _first_str(item.get("manufacture")),
                "username": _first_str(item.get("username")),
                "site_id": site_id,
                "site_name": site_name,
                "switch_mac": format_mac(smac) if smac else "",
                "switch_name": sw_name,
                "port_id": port_id,
                "port_usage": port_usage,
                "vlan": vlan_id,
                "vlan_name": vlan_name,
                "auth_state": auth_state or "server_reject",
                "auth_method": auth_method,
                "nacrule_name": _first_str(item.get("nacrule_name")),
                "reject_type": "Server Reject",
                "reason": "RADIUS / NAC Server Reject",
                "timestamp": item.get("timestamp"),
                "sources": ["wired_clients"],
            },
        )

    # Process Wired Clients sitting on a configured server_reject_network VLAN
    for item in wired_reject_vlan_list:
        cmac = normalize_mac(item.get("mac"))
        if not cmac:
            continue
        smac, port_id, vlan_id, auth_state, auth_method, port_usage = _extract_wired_port_info(item)
        if vlan_id is None or vlan_id not in reject_vlan_to_names:
            continue
        site_id = str(item.get("site_id") or "")
        sw_name, site_name = switch_label(smac, site_id)
        vlan_name = ", ".join(reject_vlan_to_names.get(vlan_id, []))
        is_explicit_sr = _is_reject_auth_state(auth_state)
        _merge_record(
            records,
            {
                "mac": format_mac(cmac),
                "hostname": _first_str(item.get("hostname")) or _first_str(item.get("dhcp_hostname")),
                "ip": _first_str(item.get("ip")),
                "manufacture": _first_str(item.get("manufacture")),
                "username": _first_str(item.get("username")),
                "site_id": site_id,
                "site_name": site_name,
                "switch_mac": format_mac(smac) if smac else "",
                "switch_name": sw_name,
                "port_id": port_id,
                "port_usage": port_usage,
                "vlan": vlan_id,
                "vlan_name": vlan_name,
                "auth_state": auth_state or "server_reject",
                "auth_method": auth_method,
                "nacrule_name": _first_str(item.get("nacrule_name")),
                "reject_type": "Server Reject" if is_explicit_sr else "Server Reject VLAN",
                "reason": f"Placed in Server Reject network ({vlan_name})",
                "timestamp": item.get("timestamp"),
                "sources": ["server_reject_vlan"],
            },
        )

    # Process Mist Access Assurance Wired NAC Denies
    for item in nac_denied_list:
        cmac = normalize_mac(item.get("mac"))
        if not cmac:
            continue
        smac = normalize_mac(item.get("device_mac") or item.get("last_device_mac") or item.get("ap"))
        port_id = str(item.get("port_id") or item.get("last_port_id") or "").strip()
        site_id = str(item.get("site_id") or "")
        sw_name, site_name = switch_label(smac, site_id)
        vlan_raw = item.get("vlan") if item.get("vlan") is not None else item.get("last_vlan_id")
        try:
            vlan_id = int(str(vlan_raw).strip()) if vlan_raw is not None and str(vlan_raw).strip() else None
        except (TypeError, ValueError):
            vlan_id = None
        vlan_name = ", ".join(reject_vlan_to_names.get(vlan_id, [])) if vlan_id is not None else ""
        rule_name = _first_str(item.get("nacrule_name") or item.get("last_nacrule_name"))
        reason = _first_str(item.get("last_status_reason") or item.get("reason"))
        if not reason:
            reason = f"NAC Access Denied{f' ({rule_name})' if rule_name else ''}"
        _merge_record(
            records,
            {
                "mac": format_mac(cmac),
                "hostname": _first_str(item.get("hostname")),
                "ip": _first_str(item.get("ip") or item.get("last_ip")),
                "manufacture": _first_str(item.get("mfg") or item.get("manufacture")),
                "username": _first_str(item.get("username") or item.get("last_username")),
                "site_id": site_id,
                "site_name": site_name,
                "switch_mac": format_mac(smac) if smac else "",
                "switch_name": sw_name,
                "port_id": port_id,
                "port_usage": "",
                "vlan": vlan_id,
                "vlan_name": vlan_name,
                "auth_state": "denied",
                "auth_method": _first_str(item.get("auth_type") or item.get("last_auth_type")),
                "nacrule_name": rule_name,
                "reject_type": "NAC Denied",
                "reason": reason,
                "timestamp": item.get("timestamp") or item.get("last_seen"),
                "sources": ["nac_clients"],
            },
        )

    # Process Switch 802.1X / Server-Reject Events
    for ev in sw_events_list:
        ev_type = str(ev.get("type") or "")
        ev_text = str(ev.get("text") or "")
        combined = f"{ev_type} {ev_text}".lower()
        if not any(tok in combined for tok in ("server_reject", "server-reject", "server reject", "dot1x", "802.1x", "radius", "auth")):
            continue
        if "reject" not in combined and "denied" not in combined:
            continue

        smac = normalize_mac(ev.get("mac") or ev.get("device_mac"))
        port_id = str(ev.get("port_id") or "").strip()
        if not port_id:
            pm = PORT_IN_TEXT_RE.search(ev_text)
            if pm:
                port_id = pm.group(0)

        cmac = normalize_mac(ev.get("client_mac"))
        if not cmac:
            for candidate in MAC_IN_TEXT_RE.findall(ev_text):
                cnorm = normalize_mac(candidate)
                if cnorm and cnorm != smac:
                    cmac = cnorm
                    break
        if not cmac and not port_id:
            continue

        site_id = str(ev.get("site_id") or "")
        sw_name, site_name = switch_label(smac, site_id)
        _merge_record(
            records,
            {
                "mac": format_mac(cmac) if cmac else f"Port {port_id}",
                "hostname": _first_str(ev.get("hostname")),
                "ip": "",
                "manufacture": "",
                "username": _first_str(ev.get("username")),
                "site_id": site_id,
                "site_name": site_name,
                "switch_mac": format_mac(smac) if smac else "",
                "switch_name": sw_name,
                "port_id": port_id,
                "port_usage": "",
                "vlan": None,
                "vlan_name": "",
                "auth_state": "server_reject",
                "auth_method": "dot1x" if "dot1x" in combined or "802.1x" in combined else "",
                "nacrule_name": "",
                "reject_type": "Server Reject",
                "reason": ev_text or ev_type or "Switch Server Reject event",
                "timestamp": ev.get("timestamp"),
                "sources": ["switch_events"],
            },
        )

    # Strictly keep only records observed within the last 24 hours
    records = {
        k: r
        for k, r in records.items()
        if isinstance(r.get("timestamp"), (int, float)) and float(r["timestamp"]) >= cutoff_ts
    }

    # Phase 3: Enrich affected switch ports with exact Port Profile (port_usage) via stats/ports/search
    affected_sw_macs = sorted(
        {normalize_mac(r.get("switch_mac")) for r in records.values() if normalize_mac(r.get("switch_mac"))}
    )
    port_lookup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if affected_sw_macs:
        # Query in chunks of 25 switch MACs so URL stays short and fast
        for i in range(0, len(affected_sw_macs), 25):
            chunk = affected_sw_macs[i : i + 25]
            ports_batch = safe_call(
                "stats_ports",
                lambda c=chunk: _mist_search_get(
                    session,
                    api_host,
                    f"/api/v1/orgs/{org_id}/stats/ports/search",
                    {"device_type": "switch", "mac": ",".join(c), "limit": 1000},
                    max_pages=2,
                ),
                [],
            )
            for p in ports_batch:
                pmac = normalize_mac(p.get("mac"))
                pid = str(p.get("port_id") or "").strip().lower()
                if pmac and pid:
                    port_lookup[(pmac, pid)] = p

    final_items: List[Dict[str, Any]] = []
    profile_counts: Dict[str, int] = {}
    affected_sites: Set[str] = set()
    affected_switches: Set[str] = set()

    for rec in records.values():
        smac = normalize_mac(rec.get("switch_mac"))
        pid = str(rec.get("port_id") or "").strip().lower()
        pinfo = port_lookup.get((smac, pid)) if (smac and pid) else None
        if pinfo:
            if not rec.get("port_usage") and pinfo.get("port_usage"):
                rec["port_usage"] = str(pinfo.get("port_usage")).strip()
            if rec.get("vlan") is None and pinfo.get("port_vlan_id") is not None:
                try:
                    rec["vlan"] = int(pinfo["port_vlan_id"])
                except (TypeError, ValueError):
                    pass
            if not rec.get("auth_state") and pinfo.get("auth_state"):
                rec["auth_state"] = str(pinfo.get("auth_state")).strip()
            rec["port_up"] = pinfo.get("up")
        else:
            rec["port_up"] = None

        # Determine if this port uses a known NAC profile (if port_usage is populated and templates exist)
        usage = rec.get("port_usage") or ""
        if usage:
            rec["is_nac_profile"] = (
                usage in nac_profile_names
                or "nac" in usage.lower()
                or "dot1x" in usage.lower()
                or rec["reject_type"] in ("Server Reject", "Server Reject VLAN", "NAC Denied")
            )
            profile_counts[usage] = profile_counts.get(usage, 0) + 1
        else:
            rec["is_nac_profile"] = True

        if rec.get("vlan") is not None and not rec.get("vlan_name") and rec["vlan"] in reject_vlan_to_names:
            rec["vlan_name"] = ", ".join(reject_vlan_to_names[rec["vlan"]])

        if rec.get("site_name"):
            affected_sites.add(rec["site_name"])
        if rec.get("switch_name"):
            affected_switches.add(rec["switch_name"])
        final_items.append(rec)

    final_items.sort(
        key=lambda r: (
            -(r.get("timestamp") or 0),
            (r.get("site_name") or "").lower(),
            (r.get("switch_name") or "").lower(),
            (r.get("port_id") or "").lower(),
        )
    )

    top_profile = None
    if profile_counts:
        top_name, top_cnt = sorted(profile_counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))[0]
        top_profile = {"name": top_name, "count": top_cnt}

    all_profiles = sorted(
        set(profile_counts.keys()) | set(nac_profile_names),
        key=lambda x: (-profile_counts.get(x, 0), x.lower()),
    )

    return {
        "duration": display_duration,
        "summary": {
            "total_rejected": len(final_items),
            "affected_switches": len(affected_switches),
            "affected_sites": len(affected_sites),
            "top_profile": top_profile,
            "configured_nac_profiles": len(nac_profile_names),
            "configured_reject_vlans": [
                {"vlan_id": vid, "labels": labels}
                for vid, labels in sorted(reject_vlan_to_names.items())
            ],
        },
        "port_profiles": all_profiles,
        "devices": final_items,
        "warnings": warnings,
    }
