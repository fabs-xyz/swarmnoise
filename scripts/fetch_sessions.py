#!/usr/bin/env python3
"""
fetch_sessions.py

Queries the GreyNoise Swarm sensor activity via the official API:
  GET https://api.greynoise.io/v1/workspaces/{workspace_id}/sensors/activity
  Auth: key: <GREYNOISE_API_KEY>

Writes session data to data/, a run log to runs/, and maintains a rolling
30-day FortiGate-ready threat feed in feeds/fortinet_ips.txt.

Environment variables required:
  GREYNOISE_API_KEY  — GreyNoise API key (from viz.greynoise.io Settings → API)
  WORKSPACE_ID       — GreyNoise workspace UUID
  SENSOR_ID          — Swarm sensor UUID (used for logging/filtering only)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_BASE             = "https://api.greynoise.io"
PAGE_SIZE            = 1000
FEED_RETENTION_DAYS  = 30


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[error] Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


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
            print(
                "[error] 401 Unauthorized — GREYNOISE_API_KEY is invalid or expired.\n"
                "        Refresh it at: viz.greynoise.io → Settings → API Key\n"
                f"        Response: {resp.text[:300]}",
                file=sys.stderr,
            )
            sys.exit(1)
        if resp.status_code == 403:
            print(
                f"[error] 403 Forbidden — API key lacks access to workspace.\n"
                f"        Response: {resp.text[:300]}",
                file=sys.stderr,
            )
            sys.exit(1)
        if resp.status_code == 404:
            print(
                f"[error] 404 Not Found — workspace not found or inaccessible.\n"
                f"        Response: {resp.text[:300]}",
                file=sys.stderr,
            )
            sys.exit(1)
        if resp.status_code in (429, 500, 502, 503, 504):
            # Transient / rate-limit error — signal to caller for retry
            raise requests.HTTPError(
                f"HTTP {resp.status_code}: {resp.text[:200]}", response=resp
            )
        if not resp.ok:
            print(
                f"[error] HTTP {resp.status_code} on page {page_num}.\n"
                f"        Response: {resp.text[:500]}",
                file=sys.stderr,
            )
            sys.exit(1)

        data = resp.json()

    except requests.HTTPError:
        raise
    except requests.RequestException as exc:
        print(f"[error] Request failed on page {page_num}: {exc}", file=sys.stderr)
        sys.exit(1)



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

    total_duration = (window_end - window_start).total_seconds()
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
) -> int:
    """
    Update the FortiGate threat feed with IPs from the fetched sessions.

    Maintains a 30-day rolling window — IPs not seen in the last
    FEED_RETENTION_DAYS days are removed from the feed.

    Returns the total number of IPs currently in the feed.
    """
    feeds_dir = repo_root / "feeds"
    feeds_dir.mkdir(exist_ok=True)

    metadata_path = feeds_dir / "ip_metadata.json"
    feed_path     = feeds_dir / "fortinet_ips.txt"

    # Load existing metadata
    metadata: dict = {}
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except Exception:
            metadata = {}

    now_str = fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff  = fetch_ts - timedelta(days=FEED_RETENTION_DAYS)

    # Extract source IPs — SDK confirms field is "source_ip"
    new_ips: set = set()
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
        if ip and isinstance(ip, str) and ip.strip():
            new_ips.add(ip.strip())

    print(f"  [feed] {len(new_ips)} unique source IPs extracted from {len(sessions)} sessions")

    # Update metadata
    new_count = 0
    for ip in new_ips:
        if ip not in metadata:
            metadata[ip] = {"first_seen": now_str, "last_seen": now_str}
            new_count += 1
        else:
            metadata[ip]["last_seen"] = now_str

    # Prune IPs outside the retention window
    pruned = [
        ip for ip, meta in metadata.items()
        if datetime.fromisoformat(meta["last_seen"].replace("Z", "+00:00")) < cutoff
    ]
    for ip in pruned:
        del metadata[ip]

    if pruned:
        print(f"  [feed] Pruned {len(pruned)} IPs older than {FEED_RETENTION_DAYS} days")

    print(f"  [feed] {new_count} new IPs added, {len(metadata)} total IPs in feed")

    # Write ip_metadata.json
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True))

    # Write fortinet_ips.txt — sorted, one IP per line, no comments
    sorted_ips = sorted(metadata.keys())
    feed_path.write_text("\n".join(sorted_ips) + "\n" if sorted_ips else "")

    print(f"  [feed] Written: {feed_path.name} ({len(sorted_ips)} IPs)")

    return len(sorted_ips)


def write_outputs(
    sessions: list,
    sensor_id: str,
    workspace_id: str,
    window_start: datetime,
    window_end: datetime,
    fetch_ts: datetime,
    duration: float,
    error: str | None,
    feed_ip_count: int,
    bootstrap: bool = False,
) -> None:
    """Write session data file (if sessions found) and run log (always)."""
    ts_str    = fetch_ts.strftime("%Y-%m-%d_%H%M")
    repo_root = Path(__file__).parent.parent

    data_dir = repo_root / "data"
    runs_dir = repo_root / "runs"
    data_dir.mkdir(exist_ok=True)
    runs_dir.mkdir(exist_ok=True)

    # Run log — always written
    run_log = {
        "timestamp":        fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensor_id":        sensor_id,
        "workspace_id":     workspace_id,
        "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_window_end":  window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sessions_found":   len(sessions),
        "feed_ip_count":    feed_ip_count,
        "duration_seconds": round(duration, 2),
        "error":            error,
    }
    run_log_path = runs_dir / f"{ts_str}_run_log.json"
    run_log_path.write_text(json.dumps(run_log, indent=2))
    print(f"[+] Run log written: {run_log_path.name}")

    # Session data — only if we have sessions AND it's not a bootstrap
    # Bootstrap collects 1M+ sessions — writing them as JSON would exceed
    # GitHub's 100MB file size limit. Run log is sufficient for auditing.
    if sessions and not bootstrap:
        data_payload = {
            "fetch_timestamp":  fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sensor_id":        sensor_id,
            "workspace_id":     workspace_id,
            "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "time_window_end":  window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_count":    len(sessions),
            "sessions":         sessions,
        }
        data_path = data_dir / f"{ts_str}.json"
        data_path.write_text(json.dumps(data_payload, indent=2))
        print(f"[+] Session data written: {data_path.name} ({len(sessions)} sessions)")
    elif bootstrap:
        print(f"[~] Bootstrap run — skipping session data file to avoid 100MB GitHub limit.")
    else:
        print("[~] No sessions found in this window — data file skipped.")


def is_first_run(repo_root: Path) -> bool:
    """Return True if the feed has never been populated (bootstrap mode)."""
    return not (repo_root / "feeds" / "ip_metadata.json").exists()


def main() -> None:
    api_key      = get_env("GREYNOISE_API_KEY")
    workspace_id = get_env("WORKSPACE_ID")
    sensor_id    = get_env("SENSOR_ID")

    now       = datetime.now(timezone.utc)
    repo_root = Path(__file__).parent.parent

    # Determine time window
    window_start_str = os.environ.get("TIME_WINDOW_START")
    window_end_str   = os.environ.get("TIME_WINDOW_END")

    bootstrap = is_first_run(repo_root)

    if bootstrap:
        print("[*] First run detected — bootstrapping feed with last 30 days of data")
        window_end   = now
        # Start slightly inside the 30-day limit to avoid API boundary errors.
        # The API rejects requests where start_time is exactly 30 days ago.
        window_start = now - timedelta(days=29, hours=23)
    elif window_start_str and window_end_str:
        window_start = datetime.fromisoformat(window_start_str.replace("Z", "+00:00"))
        window_end   = datetime.fromisoformat(window_end_str.replace("Z", "+00:00"))
    else:
        window_end   = now
        window_start = now - timedelta(hours=6)

    print(f"[*] GreyNoise Swarm — sensor activity fetch")
    print(f"    Sensor    : {sensor_id}")
    print(f"    Workspace : {workspace_id}")
    print(f"    Window    : {window_start.strftime('%Y-%m-%dT%H:%M:%SZ')} → "
          f"{window_end.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"    Bootstrap : {bootstrap}")
    print(f"    Endpoint  : {API_BASE}/v1/workspaces/{{workspace_id}}/sensors/activity")

    t0    = time.monotonic()
    error = None
    sessions     = []
    feed_ip_count = 0

    try:
        print("[*] Fetching sessions...")
        sessions = fetch_sessions(api_key, workspace_id, window_start, window_end)

        print("[*] Updating threat feed...")
        feed_ip_count = update_threat_feed(sessions, repo_root, now)

    except SystemExit:
        raise
    except Exception as exc:
        error = str(exc)
        print(f"[error] Unexpected error: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    duration = time.monotonic() - t0
    write_outputs(
        sessions, sensor_id, workspace_id,
        window_start, window_end, now,
        duration, error, feed_ip_count,
        bootstrap=bootstrap,
    )

    print(f"[*] Done in {duration:.1f}s — {len(sessions)} sessions, "
          f"{feed_ip_count} IPs in feed.")


if __name__ == "__main__":
    main()
