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


def fetch_sessions(
    api_key: str,
    workspace_id: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """
    Fetch all sessions for the workspace within the time window.

    Uses api.greynoise.io/v1/workspaces/{workspace_id}/sensors/activity
    with standard key: header auth and scroll-based pagination.
    """
    url = f"{API_BASE}/v1/workspaces/{workspace_id}/sensors/activity"
    headers = {
        "key": api_key,
        "Accept": "application/json",
    }

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
        if scroll:
            params["scroll"] = scroll

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=60)
            print(f"  [page {page}] HTTP {resp.status_code}")

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
                    f"[error] 403 Forbidden — API key lacks access to workspace {workspace_id}.\n"
                    f"        Response: {resp.text[:300]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if resp.status_code == 404:
                print(
                    f"[error] 404 Not Found — workspace {workspace_id} does not exist or is inaccessible.\n"
                    f"        Response: {resp.text[:300]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if not resp.ok:
                print(
                    f"[error] HTTP {resp.status_code} on page {page}.\n"
                    f"        Response: {resp.text[:500]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            data = resp.json()

        except requests.RequestException as exc:
            print(f"[error] Request failed on page {page}: {exc}", file=sys.stderr)
            sys.exit(1)

        # Print response structure on first page for debugging
        if page == 1:
            if isinstance(data, dict):
                print(f"  [page 1] Response keys: {list(data.keys())}")
            elif isinstance(data, list):
                print(f"  [page 1] Response: list of {len(data)} items")
                if data:
                    print(f"  [page 1] First item keys: {list(data[0].keys()) if isinstance(data[0], dict) else type(data[0])}")
            else:
                print(f"  [page 1] Unexpected response type: {type(data)}")

        # Extract sessions — API returns a list directly or wrapped in a dict
        if isinstance(data, list):
            page_sessions = data
            # Scroll token may come from response headers
            scroll = resp.headers.get("X-Scroll") or resp.headers.get("scroll") or None
        elif isinstance(data, dict):
            page_sessions = (
                data.get("data")
                or data.get("sessions")
                or data.get("items")
                or data.get("results")
                or []
            )
            # Scroll token may be in body or headers
            scroll = (
                data.get("scroll")
                or data.get("next_scroll")
                or resp.headers.get("X-Scroll")
                or resp.headers.get("scroll")
                or None
            )
        else:
            page_sessions = []
            scroll = None

        sessions.extend(page_sessions)
        print(f"  [page {page}] {len(page_sessions)} sessions (total: {len(sessions)})")

        if page == 1 and not page_sessions:
            print(f"  [debug] Full response (truncated):\n{json.dumps(data, indent=2)[:2000]}")

        # Stop when page is under full size, or no scroll token
        if len(page_sessions) < PAGE_SIZE or not scroll:
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

    # Session data — only if we have sessions
    if sessions:
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
        window_start = now - timedelta(days=30)
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
    )

    print(f"[*] Done in {duration:.1f}s — {len(sessions)} sessions, "
          f"{feed_ip_count} IPs in feed.")


if __name__ == "__main__":
    main()
