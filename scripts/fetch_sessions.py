#!/usr/bin/env python3
"""
fetch_sessions.py

Queries the GreyNoise Swarm sensor activity via two API endpoints:

  1. Full feed (v1):
     GET https://api.greynoise.io/v1/workspaces/{workspace_id}/sensors/activity
     Returns all sessions — used for the full IP blocklist.

  2. Filtered feed (v3):
     GET https://api.greynoise.io/v3/sessions
     Supports Lucene query filtering — used to extract malicious and suspicious sessions
     and their enriched metadata (tags, CVEs, source geo, etc.).

Auth: key: <GREYNOISE_API_KEY>

Writes session data to data/, a run log to runs/, and maintains three rolling
30-day firewall-compatible threat feeds in feeds/:
  - threat_feed.txt                   — all attacker IPs
  - threat_feed_filtered.txt          — confirmed malicious and suspicious IPs
  - threat_feed_high_confidence.txt   — multi-sensor OR malicious-only IPs
  - filtered_metadata.json            — per-IP enriched metadata from v3 sessions

Environment variables required:
  GREYNOISE_API_KEY  — GreyNoise API key (from viz.greynoise.io Settings → API)
  WORKSPACE_ID       — GreyNoise workspace UUID
  SENSOR_IDS         — Comma-separated uuid:label pairs (e.g. "uuid1:berlin,uuid2:tokyo")
                       Falls back to SENSOR_ID (single sensor, label "default").
"""

import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE             = "https://api.greynoise.io"
PAGE_SIZE            = 1000
FEED_RETENTION_DAYS  = 30


class SwarmNoiseError(Exception):
    pass


class ConfigError(SwarmNoiseError):
    pass


class APIError(SwarmNoiseError):
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


def atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    tmp.replace(path)


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Required environment variable {name} is not set")
    return value


def parse_sensor_ids() -> dict[str, str]:
    """
    Parse SENSOR_IDS env var into a {uuid: label} mapping.

    Format: "uuid1:berlin,uuid2:tokyo,uuid3:amsterdam"
    Falls back to SENSOR_ID with label "default" if SENSOR_IDS is not set.
    """
    raw = os.environ.get("SENSOR_IDS", "").strip()
    if raw:
        sensor_map: dict[str, str] = {}
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                uuid, label = entry.split(":", 1)
                sensor_map[uuid.strip()] = label.strip()
            else:
                sensor_map[entry] = "default"
        return sensor_map

    fallback = os.environ.get("SENSOR_ID", "").strip()
    if fallback:
        return {fallback: "default"}

    print("[error] Neither SENSOR_IDS nor SENSOR_ID is set.", file=sys.stderr)
    raise ConfigError("Neither SENSOR_IDS nor SENSOR_ID is set")


def _extract_sensor_id(session: dict) -> str | None:
    """Extract the sensor identifier from a session object (v1 or v3)."""
    return (
        session.get("sensor_id")
        or session.get("sensorId")
        or (session.get("sensor") or {}).get("id")
        or (session.get("sensor") or {}).get("_id")
        or session.get("sensorIdStr")
        or session.get("sensor_id_str")
    )


def _fetch_page(
    url: str,
    headers: dict,
    params: dict,
    page_num: int,
) -> tuple:
    """
    Fetch one page from the sensor activity API.
    Returns (sessions_list, scroll_token_or_None, raw_response_headers).
    Exits on HTTP errors.
    """
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        print(f"  [page {page_num}] HTTP {resp.status_code}")

        if resp.status_code == 401:
            raise APIError(f"Unauthorized (HTTP {resp.status_code})", status_code=resp.status_code)
        if resp.status_code == 403:
            raise APIError(f"Forbidden (HTTP {resp.status_code})", status_code=resp.status_code)
        if resp.status_code == 404:
            raise APIError(f"HTTP {resp.status_code}: {resp.text[:200]}", status_code=resp.status_code)
        if resp.status_code in (429, 500, 502, 503, 504):
            raise requests.HTTPError(
                f"HTTP {resp.status_code}: {resp.text[:200]}", response=resp
            )
        if not resp.ok:
            raise APIError(f"HTTP {resp.status_code}: {resp.text[:200]}", status_code=resp.status_code)

        data = resp.json()

    except requests.HTTPError:
        raise
    except requests.RequestException as exc:
        raise APIError(f"Request failed on page {page_num}: {exc}")



    # Extract sessions
    if isinstance(data, list):
        page_sessions = data
    elif isinstance(data, dict):
        page_sessions = (
            data.get("data")
            or data.get("sessions")
            or data.get("items")
            or data.get("results")
            or []
        )
    else:
        page_sessions = []

    if page_num == 1 and not page_sessions:
        print(f"  [debug] Full response body (truncated):\n{json.dumps(data, indent=2)[:2000]}")

    # Extract scroll token — check every plausible location
    scroll = None
    if isinstance(data, dict):
        scroll = (
            data.get("scroll")
            or data.get("next_scroll")
            or data.get("scrollToken")
            or data.get("cursor")
            or data.get("next_cursor")
            or data.get("nextCursor")
        )
    if not scroll:
        # Check response headers (case-insensitive)
        h = {k.lower(): v for k, v in resp.headers.items()}
        scroll = (
            h.get("x-scroll-id")
            or h.get("x-scroll")
            or h.get("scroll")
            or h.get("x-cursor")
            or h.get("cursor")
            or h.get("x-next-scroll")
        )

    return page_sessions, scroll, dict(resp.headers)


def fetch_sessions(
    api_key: str,
    workspace_id: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """
    Fetch all sessions for the workspace within the time window.

    Strategy:
    1. Try scroll-based pagination first (up to MAX_SCROLL_PAGES pages).
    2. If the API caps at 1000 and returns no scroll token, fall back to
       time-chunking: split the window into CHUNK_HOURS-hour slices and
       fetch each independently. This guarantees full coverage regardless
       of whether the API exposes a scroll mechanism.
    """
    url = f"{API_BASE}/v1/workspaces/{workspace_id}/sensors/activity"
    req_headers = {
        "key": api_key,
        "Accept": "application/json",
    }

    # The X-Scroll-Id token (~8KB base64) cannot be passed back either as a
    # query param (HTTP 414) or as a request header (HTTP 400 header too large).
    # Strategy: use 30-minute time chunks. At ~167 sessions/hour observed rate,
    # 30-min chunks yield ~83 sessions — well under the 1000-session cap.
    # If a chunk still hits 1000 we log a warning but continue (some sessions
    # in high-traffic hours may be missed — acceptable for a threat feed).
    # 30-day bootstrap = 1440 chunks (~24 min at 1 req/s).
    CHUNK_SECONDS    = 30 * 60   # 30 minutes
    MAX_SCROLL_PAGES = 1         # never attempt scroll (token unusable)

    # Always chunk — even short windows use the same path for simplicity
    print(f"  [fetch] Chunking into {CHUNK_SECONDS // 60}-min windows (scroll disabled)")
    all_sessions = []
    chunk_start  = window_start
    chunk_num    = 0

    while chunk_start < window_end:
        chunk_end  = min(chunk_start + timedelta(seconds=CHUNK_SECONDS), window_end)
        chunk_num += 1
        print(f"  [chunk {chunk_num}] {chunk_start.strftime('%Y-%m-%dT%H:%MZ')} → "
              f"{chunk_end.strftime('%Y-%m-%dT%H:%MZ')}")
        chunk_sessions = _fetch_window_scrolled(
            url, req_headers, workspace_id,
            chunk_start, chunk_end,
            MAX_SCROLL_PAGES,
        )
        all_sessions.extend(chunk_sessions)
        if len(chunk_sessions) >= PAGE_SIZE:
            print(f"  [warning] chunk {chunk_num} hit the {PAGE_SIZE}-session cap — "
                  f"some sessions in this window may be missed")
        print(f"  [chunk {chunk_num}] {len(chunk_sessions)} sessions "
              f"(running total: {len(all_sessions)})")
        chunk_start = chunk_end
        time.sleep(0.5)  # avoid rate-limit 500s

    if all_sessions and os.environ.get("DEBUG_SESSION_KEYS", "").strip().lower() in ("1", "true", "yes"):
        sample = all_sessions[0]
        if isinstance(sample, dict):
            print(f"  [debug] v1 session keys: {sorted(sample.keys())}")
            sensor_val = _extract_sensor_id(sample)
            print(f"  [debug] v1 sensor field value: {sensor_val}")

    return all_sessions


def _fetch_window_scrolled(
    url: str,
    req_headers: dict,
    workspace_id: str,  # kept for symmetry / future use
    window_start: datetime,
    window_end: datetime,
    max_pages: int,
) -> list:
    """Fetch a single time window with scroll pagination."""
    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str   = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    sessions = []
    page     = 1
    scroll   = None

    while True:
        params: dict = {
            "format":     "json",
            "start_time": start_str,
            "end_time":   end_str,
            "size":       PAGE_SIZE,
        }
        # Pass scroll token as a request header, NOT as a query param.
        # The X-Scroll-Id value is ~8KB of base64 and causes HTTP 414 when
        # URL-encoded in the query string. The API echoes it via the header
        # so we mirror it back the same way.
        extra_headers = {}
        if scroll:
            extra_headers["X-Scroll-Id"] = scroll

        merged_headers = {**req_headers, **extra_headers}

        # Retry transient errors (429/5xx) up to 3 times with backoff
        for attempt in range(1, 4):
            try:
                page_sessions, scroll, _ = _fetch_page(url, merged_headers, params, page)
                break
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                if attempt < 3:
                    wait = 30 * attempt
                    print(f"    [retry] HTTP {status} on attempt {attempt} — "
                          f"waiting {wait}s before retry")
                    time.sleep(wait)
                else:
                    print(
                        f"[error] HTTP {status} after 3 attempts — giving up on this chunk.\n"
                        f"        {exc}",
                        file=sys.stderr,
                    )
                    sys.exit(1)

        sessions.extend(page_sessions)
        print(f"    [scroll page {page}] {len(page_sessions)} sessions "
              f"(window total: {len(sessions)}, scroll: {'yes' if scroll else 'no'})")

        if len(page_sessions) < PAGE_SIZE or not scroll or page >= max_pages:
            if page >= max_pages and scroll:
                print(f"    [scroll] Reached max_pages={max_pages} limit — "
                      f"time-chunker will cover remaining data via smaller windows")
            break
        page += 1

    return sessions


def update_threat_feed(
    sessions: list,
    repo_root: Path,
    fetch_ts: datetime,
    sensor_map: dict[str, str] | None = None,
) -> int:
    """
    Update the firewall-compatible threat feed with IPs from the fetched sessions.

    Maintains a 30-day rolling window — IPs not seen in the last
    FEED_RETENTION_DAYS days are removed from the feed.

    Returns a tuple of (total IP count, metadata dict).
    """
    feeds_dir = repo_root / "feeds"
    feeds_dir.mkdir(exist_ok=True)

    metadata_path = feeds_dir / "ip_metadata.json"
    feed_path     = feeds_dir / "threat_feed.txt"

    metadata: dict = {}
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] Corrupt file {metadata_path.name}: {exc} — backing up and resetting", file=sys.stderr)
            corrupt_path = metadata_path.with_suffix(metadata_path.suffix + ".corrupt")
            metadata_path.rename(corrupt_path)

    now_str = fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff  = fetch_ts - timedelta(days=FEED_RETENTION_DAYS)

    ip_sensors: dict[str, set[str]] = {}
    for session in sessions:
        if not isinstance(session, dict):
            continue
        ip = (
            session.get("source_ip")
            or (session.get("source") or {}).get("ip")
            or session.get("source.ip")
            or session.get("srcIp")
            or session.get("src_ip")
            or session.get("sourceIp")
        )
        if not ip or not isinstance(ip, str) or not ip.strip():
            continue
        ip = ip.strip()

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[!] Skipping invalid IP: {ip}", file=sys.stderr)
            continue

        sensor_uuid = _extract_sensor_id(session) if sensor_map else None
        label = sensor_map.get(sensor_uuid, "unknown") if sensor_uuid and sensor_map else None

        if ip not in ip_sensors:
            ip_sensors[ip] = set()
        if label:
            ip_sensors[ip].add(label)

    new_ips = set(ip_sensors.keys())
    print(f"  [feed] {len(new_ips)} unique source IPs extracted from {len(sessions)} sessions")

    new_count = 0
    for ip in new_ips:
        sensors = ip_sensors.get(ip, set())
        if ip not in metadata:
            metadata[ip] = {
                "first_seen": now_str,
                "last_seen": now_str,
                "seen_by": sorted(sensors) if sensors else [],
            }
            new_count += 1
        else:
            entry = metadata[ip]
            entry["last_seen"] = now_str
            existing = set(entry.get("seen_by", []))
            merged = sorted(existing | sensors) if sensors else sorted(existing)
            entry["seen_by"] = merged

    pruned = [
        ip for ip, meta in metadata.items()
        if datetime.fromisoformat(meta["last_seen"].replace("Z", "+00:00")) < cutoff
    ]
    for ip in pruned:
        del metadata[ip]

    if pruned:
        print(f"  [feed] Pruned {len(pruned)} IPs older than {FEED_RETENTION_DAYS} days")

    print(f"  [feed] {new_count} new IPs added, {len(metadata)} total IPs in feed")

    atomic_write(metadata_path, json.dumps(metadata, indent=2, sort_keys=True))

    sorted_ips = sorted(metadata.keys())
    atomic_write(feed_path, "\n".join(sorted_ips) + "\n" if sorted_ips else "")

    print(f"  [feed] Written: {feed_path.name} ({len(sorted_ips)} IPs)")

    return len(sorted_ips), metadata


V3_PAGE_SIZE          = 100
FILTERED_QUERY        = "classification:malicious OR classification:suspicious"
FILTERED_CHUNK_HOURS  = 6


def _v3_fetch_page(
    api_key: str,
    start_time: datetime,
    end_time: datetime,
    query: str,
    page: int,
    page_size: int = V3_PAGE_SIZE,
    retries: int = 3,
) -> tuple:
    """
    Fetch one page from the v3 sessions API.
    Returns (sessions_list, total_count).
    """
    params = {
        "scope":      "workspace",
        "start_time": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time":   end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "query":      query,
        "page":       page,
        "page_size":  page_size,
    }
    headers = {"key": api_key, "Accept": "application/json"}

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(
                f"{API_BASE}/v3/sessions",
                headers=headers,
                params=params,
                timeout=60,
            )

            if resp.status_code in (429, 500, 502, 503, 504):
                wait = 30 if resp.status_code == 429 else 15
                print(f"  [v3 page {page}] HTTP {resp.status_code} — "
                      f"retry {attempt}/{retries} in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue

            if resp.status_code in (401, 403):
                raise APIError(f"v3 sessions HTTP {resp.status_code}: {resp.text[:300]}", status_code=resp.status_code)

            if not resp.ok:
                print(f"[error] v3 sessions HTTP {resp.status_code} on page {page}: "
                      f"{resp.text[:300]}", file=sys.stderr)
                return [], 0

            data = resp.json()
            return data.get("sessions", []), data.get("total", 0)

        except requests.RequestException as exc:
            print(f"  [v3 page {page}] Request error (attempt {attempt}): {exc}",
                  file=sys.stderr)
            if attempt < retries:
                time.sleep(15)

    return [], 0


def fetch_filtered_sessions(
    api_key: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """
    Fetch malicious and suspicious sessions via v3/sessions.
    Uses time-chunking (6-hour windows) and page-based pagination.
    Returns all matching session objects with full metadata.
    """
    chunk_duration = timedelta(hours=FILTERED_CHUNK_HOURS)
    all_sessions   = []
    chunk_start    = window_start
    chunk_num      = 0

    while chunk_start < window_end:
        chunk_end = min(chunk_start + chunk_duration, window_end)
        chunk_num += 1

        page      = 1
        collected = 0
        total     = None

        while True:
            sessions, total = _v3_fetch_page(
                api_key, chunk_start, chunk_end,
                FILTERED_QUERY, page,
            )

            if total is None:
                total = 0

            if not sessions:
                break

            all_sessions.extend(sessions)
            collected += len(sessions)

            if collected >= total or len(sessions) < V3_PAGE_SIZE:
                break

            page += 1
            time.sleep(0.3)

        if collected > 0:
            print(f"  [v3 chunk {chunk_num}] "
                  f"{chunk_start.strftime('%Y-%m-%dT%H:%MZ')} → "
                  f"{chunk_end.strftime('%Y-%m-%dT%H:%MZ')}: "
                  f"{collected} malicious+suspicious sessions")

        chunk_start = chunk_end
        time.sleep(0.3)

    print(f"  [v3] Total filtered sessions fetched: {len(all_sessions)}")

    if all_sessions and os.environ.get("DEBUG_SESSION_KEYS", "").strip().lower() in ("1", "true", "yes"):
        sample = all_sessions[0]
        if isinstance(sample, dict):
            print(f"  [debug] v3 session keys: {sorted(sample.keys())}")
            sensor_val = _extract_sensor_id(sample)
            print(f"  [debug] v3 sensor field value: {sensor_val}")

    return all_sessions


def update_filtered_feed(
    filtered_sessions: list,
    repo_root: Path,
    fetch_ts: datetime,
    sensor_map: dict[str, str] | None = None,
    ip_metadata: dict | None = None,
) -> int:
    """
    Update the filtered threat feed and per-IP metadata from v3 session data.

    Writes:
      - feeds/threat_feed_filtered.txt  (malicious and suspicious IPs, one per line)
      - feeds/filtered_metadata.json    (enriched per-IP metadata)

    Maintains a 30-day rolling window.

    Returns the number of IPs in the filtered feed.
    """
    feeds_dir = repo_root / "feeds"
    feeds_dir.mkdir(exist_ok=True)

    metadata_path = feeds_dir / "filtered_metadata.json"
    feed_path     = feeds_dir / "threat_feed_filtered.txt"

    metadata: dict = {}
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] Corrupt file {metadata_path.name}: {exc} — backing up and resetting", file=sys.stderr)
            corrupt_path = metadata_path.with_suffix(metadata_path.suffix + ".corrupt")
            metadata_path.rename(corrupt_path)

    now_str = fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff  = fetch_ts - timedelta(days=FEED_RETENTION_DAYS)

    for session in filtered_sessions:
        if not isinstance(session, dict):
            continue

        ip = (session.get("source") or {}).get("ip")
        if not ip or not isinstance(ip, str):
            continue

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[!] Skipping invalid IP: {ip}", file=sys.stderr)
            continue

        src_meta = session.get("sourceMetadata") or {}
        tags     = session.get("gnTagMetadata") or session.get("tag") or []

        tag_names     = sorted(set(t.get("name") for t in tags if t.get("name")))
        tag_categories = sorted(set(t.get("category") for t in tags if t.get("category")))
        tag_cves_flat = []
        for t in tags:
            for cve in (t.get("cves") or []):
                tag_cves_flat.append(cve)
        tag_cves = sorted(set(tag_cves_flat))

        intentions = sorted(set(
            t.get("intention") for t in tags if t.get("intention")
        ))

        dest_port = (session.get("destination") or {}).get("port")
        protocols = session.get("protocol") or []

        suricata = session.get("suricata") or {}
        suricata_signatures = suricata.get("signature") or []

        sensor_uuid = _extract_sensor_id(session) if sensor_map else None
        sensor_label = sensor_map.get(sensor_uuid, "unknown") if sensor_uuid and sensor_map else None

        if ip not in metadata:
            metadata[ip] = {
                "first_seen":         now_str,
                "last_seen":          now_str,
                "classification":     session.get("classification", "unknown"),
                "tags":               tag_names,
                "tag_categories":     tag_categories,
                "tag_intentions":     intentions,
                "cves":               tag_cves,
                "country":            src_meta.get("country"),
                "country_code":       src_meta.get("country_code"),
                "asn":                src_meta.get("asn"),
                "org":                src_meta.get("org"),
                "is_vpn":             src_meta.get("is_vpn"),
                "is_tor":             src_meta.get("is_tor"),
                "is_bot":             src_meta.get("is_bot"),
                "rdns":               src_meta.get("rdns"),
                "destination_ports":  sorted(set(filter(None, [dest_port]))),
                "protocols":          sorted(set(protocols)) if isinstance(protocols, list) else [],
                "suricata_signatures": sorted(set(suricata_signatures)),
                "seen_by":            [sensor_label] if sensor_label else [],
            }
        else:
            entry = metadata[ip]
            entry["last_seen"] = now_str
            entry["tags"]          = sorted(set(entry.get("tags", []) + tag_names))
            entry["tag_categories"] = sorted(set(entry.get("tag_categories", []) + tag_categories))
            entry["tag_intentions"] = sorted(set(entry.get("tag_intentions", []) + intentions))
            entry["cves"]          = sorted(set(entry.get("cves", []) + tag_cves))
            if dest_port:
                ports = entry.get("destination_ports", [])
                if dest_port not in ports:
                    ports.append(dest_port)
                    entry["destination_ports"] = sorted(ports)
            if isinstance(protocols, list):
                entry["protocols"] = sorted(set(entry.get("protocols", []) + protocols))
            if suricata_signatures:
                entry["suricata_signatures"] = sorted(set(
                    entry.get("suricata_signatures", []) + suricata_signatures
                ))
            if sensor_label:
                existing = set(entry.get("seen_by", []))
                existing.add(sensor_label)
                entry["seen_by"] = sorted(existing)

    pruned = [
        ip for ip, meta in metadata.items()
        if datetime.fromisoformat(meta["last_seen"].replace("Z", "+00:00")) < cutoff
    ]
    for ip in pruned:
        del metadata[ip]

    if pruned:
        print(f"  [filtered feed] Pruned {len(pruned)} IPs older than "
              f"{FEED_RETENTION_DAYS} days")

    for ip, entry in metadata.items():
        if ip_metadata and ip in ip_metadata:
            ip_seen = ip_metadata[ip].get("seen_by", [])
            existing = set(entry.get("seen_by", []))
            merged = sorted(existing | set(ip_seen))
            entry["seen_by"] = merged
        entry["multi_sensor"] = len(entry.get("seen_by", [])) >= 2

    atomic_write(metadata_path, json.dumps(metadata, indent=2, sort_keys=True))

    sorted_ips = sorted(metadata.keys())
    atomic_write(feed_path, "\n".join(sorted_ips) + "\n" if sorted_ips else "")

    print(f"  [filtered feed] {len(sorted_ips)} malicious+suspicious IPs → {feed_path.name}")
    print(f"  [filtered feed] Metadata → {metadata_path.name}")

    return len(sorted_ips)


def update_high_confidence_feed(
    repo_root: Path,
) -> int:
    """
    Generate the high-confidence feed from filtered_metadata.json.

    Includes IPs that are either:
      - corroborated by 2+ sensors (multi_sensor: true), OR
      - classified as malicious

    Returns the number of IPs in the high-confidence feed.
    """
    feeds_dir = repo_root / "feeds"
    metadata_path = feeds_dir / "filtered_metadata.json"
    feed_path     = feeds_dir / "threat_feed_high_confidence.txt"

    if not metadata_path.exists():
        atomic_write(feed_path, "")
        return 0

    try:
        metadata = json.loads(metadata_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Corrupt file {metadata_path.name}: {exc} — backing up and resetting", file=sys.stderr)
        corrupt_path = metadata_path.with_suffix(metadata_path.suffix + ".corrupt")
        metadata_path.rename(corrupt_path)
        metadata = {}

    high_confidence = [
        ip for ip, entry in metadata.items()
        if isinstance(entry, dict)
        and (entry.get("multi_sensor") or entry.get("classification") == "malicious")
    ]

    sorted_ips = sorted(high_confidence)
    atomic_write(feed_path, "\n".join(sorted_ips) + "\n" if sorted_ips else "")

    print(f"  [high confidence] {len(sorted_ips)} IPs → {feed_path.name}")
    return len(sorted_ips)


def write_outputs(
    sessions: list,
    sensor_map: dict[str, str],
    workspace_id: str,
    window_start: datetime,
    window_end: datetime,
    fetch_ts: datetime,
    duration: float,
    error: str | None,
    feed_ip_count: int,
    filtered_ip_count: int = 0,
    high_confidence_ip_count: int = 0,
    bootstrap: bool = False,
) -> None:
    """Write session data file (if sessions found) and run log (always)."""
    ts_str    = fetch_ts.strftime("%Y-%m-%d_%H%M")
    repo_root = Path(__file__).parent.parent

    data_dir = repo_root / "data"
    runs_dir = repo_root / "runs"
    data_dir.mkdir(exist_ok=True)
    runs_dir.mkdir(exist_ok=True)

    run_log = {
        "timestamp":                 fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_window_start":         window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_window_end":           window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sessions_found":            len(sessions),
        "feed_ip_count":             feed_ip_count,
        "filtered_ip_count":         filtered_ip_count,
        "high_confidence_ip_count":  high_confidence_ip_count,
        "sensor_count":              len(sensor_map),
        "duration_seconds":          round(duration, 2),
        "error":                     error,
    }
    run_log_path = runs_dir / f"{ts_str}_run_log.json"
    atomic_write(run_log_path, json.dumps(run_log, indent=2))
    print(f"[+] Run log written: {run_log_path.name}")

    if sessions and not bootstrap:
        data_payload = {
            "fetch_timestamp":  fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sensor_map":       sensor_map,
            "workspace_id":     workspace_id,
            "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "time_window_end":  window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_count":    len(sessions),
            "sessions":         sessions,
        }
        data_path = data_dir / f"{ts_str}.json"
        atomic_write(data_path, json.dumps(data_payload, indent=2))
        print(f"[+] Session data written: {data_path.name} ({len(sessions)} sessions)")
    elif bootstrap:
        print("[~] Bootstrap run — skipping session data file to avoid 100MB GitHub limit.")
    else:
        print("[~] No sessions found in this window — data file skipped.")


def is_first_run(repo_root: Path) -> bool:
    """Return True if the feed has never been populated (bootstrap mode)."""
    return not (repo_root / "feeds" / "ip_metadata.json").exists()


def main() -> None:
    api_key      = get_env("GREYNOISE_API_KEY")
    workspace_id = get_env("WORKSPACE_ID")
    sensor_map   = parse_sensor_ids()

    now       = datetime.now(timezone.utc)
    repo_root = Path(__file__).parent.parent

    window_start_str = os.environ.get("TIME_WINDOW_START")
    window_end_str   = os.environ.get("TIME_WINDOW_END")

    bootstrap = is_first_run(repo_root)

    if bootstrap:
        print("[*] First run detected — bootstrapping feed with last 30 days of data")
        window_end   = now
        window_start = now - timedelta(days=29, hours=23)
    elif window_start_str and window_end_str:
        window_start = datetime.fromisoformat(window_start_str.replace("Z", "+00:00"))
        window_end   = datetime.fromisoformat(window_end_str.replace("Z", "+00:00"))
    else:
        window_end   = now
        window_start = now - timedelta(hours=6)

    print("[*] GreyNoise Swarm — sensor activity fetch")
    print(f"    Sensors   : {len(sensor_map)} — {', '.join(f'{k[:8]}...→{v}' for k, v in sensor_map.items())}")
    print(f"    Workspace : {workspace_id}")
    print(f"    Window    : {window_start.strftime('%Y-%m-%dT%H:%M:%SZ')} → "
          f"{window_end.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"    Bootstrap : {bootstrap}")

    t0    = time.monotonic()
    error = None
    sessions       = []
    feed_ip_count  = 0
    filtered_count = 0
    hc_count       = 0
    ip_meta: dict  = {}

    try:
        print("[*] Fetching all sessions (v1 API)...")
        sessions = fetch_sessions(api_key, workspace_id, window_start, window_end)

        print("[*] Updating full threat feed...")
        feed_ip_count, ip_meta = update_threat_feed(
            sessions, repo_root, now, sensor_map=sensor_map,
        )

        print("[*] Fetching malicious sessions (v3 API)...")
        filtered_sessions = fetch_filtered_sessions(
            api_key, window_start, window_end,
        )

        print("[*] Updating filtered feed + metadata...")
        filtered_count = update_filtered_feed(
            filtered_sessions, repo_root, now,
            sensor_map=sensor_map, ip_metadata=ip_meta,
        )

        print("[*] Generating high-confidence feed...")
        hc_count = update_high_confidence_feed(repo_root)

    except SwarmNoiseError as exc:
        error = str(exc)
        print(f"[error] {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    except Exception as exc:
        error = str(exc)
        print(f"[error] Unexpected error: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    duration = time.monotonic() - t0
    write_outputs(
        sessions, sensor_map, workspace_id,
        window_start, window_end, now,
        duration, error, feed_ip_count,
        filtered_ip_count=filtered_count,
        high_confidence_ip_count=hc_count,
        bootstrap=bootstrap,
    )

    print(f"[*] Done in {duration:.1f}s — {len(sessions)} sessions, "
          f"{feed_ip_count} IPs in full feed, {filtered_count} in filtered feed, "
          f"{hc_count} in high-confidence feed.")


if __name__ == "__main__":
    main()
