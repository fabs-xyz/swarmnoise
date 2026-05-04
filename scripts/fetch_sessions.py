#!/usr/bin/env python3
"""
fetch_sessions.py

Queries the GreyNoise Swarm session API for all sessions observed by the
configured sensor. Writes session data to data/, a run log to runs/, and
maintains a rolling 30-day FortiGate-ready threat feed in feeds/.

API endpoint (discovered via browser DevTools at viz.greynoise.io):
  GET https://viz.greynoise.io/api/greynoise/workspace/sessions
  Auth header: token: <workspaceApiKey>

Environment variables required:
  GREYNOISE_API_KEY  — workspaceApiKey from viz.greynoise.io (the stable API key,
                       found in the cookie 'workspaceApiKey' or Settings → API)
  WORKSPACE_ID       — GreyNoise workspace UUID
  SENSOR_ID          — Swarm sensor UUID
  TIME_WINDOW_START  — ISO8601 UTC start of fetch window (optional,
                       defaults to 6 hours ago, or 30 days on first run)
  TIME_WINDOW_END    — ISO8601 UTC end of fetch window (optional,
                       defaults to now)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration — confirmed via browser DevTools at viz.greynoise.io
# ---------------------------------------------------------------------------
SESSIONS_URL = "https://viz.greynoise.io/api/greynoise/workspace/sessions"
PAGE_SIZE = 500          # UI uses 50; increase for efficiency (test if server caps it)
FEED_RETENTION_DAYS = 30


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[error] Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def fetch_sessions(
    api_key: str,
    sensor_id: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """
    Fetch all sessions for the sensor within the time window.

    Uses the viz.greynoise.io proxy API with token auth and page-based pagination.
    """
    headers = {
        "token": api_key,
        "Accept": "application/json",
        "Referer": "https://viz.greynoise.io/observe/explore/sessions",
    }

    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Filter to our sensor only
    query = f"gnMetadata.sensor.id:{sensor_id}"

    sessions = []
    page = 1

    while True:
        params = {
            "query": query,
            "start_time": start_str,
            "end_time": end_str,
            "page": page,
            "page_size": PAGE_SIZE,
            "sort_by": "lastPacket",
            "sort_desc": "true",
        }

        try:
            resp = requests.get(SESSIONS_URL, headers=headers, params=params, timeout=60)
            print(f"  [page {page}] HTTP {resp.status_code}")

            if resp.status_code == 401:
                print(
                    "[error] Authentication failed (401). The GREYNOISE_API_KEY secret\n"
                    "        may be expired or incorrect.\n"
                    "        To refresh: log into viz.greynoise.io, open DevTools → Network,\n"
                    "        run a session search, and copy the 'token' request header value.\n"
                    "        Then update the secret:\n"
                    "          gh secret set GREYNOISE_API_KEY --repo fabs-xyz/swarmnoise\n"
                    f"        Response: {resp.text[:300]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if resp.status_code == 403:
                print(
                    "[error] Forbidden (403). The token may lack access to this workspace.\n"
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
            keys = list(data.keys()) if isinstance(data, dict) else type(data).__name__
            print(f"  [page 1] Response keys: {keys}")

        # Extract sessions — handle various response shapes
        if isinstance(data, list):
            page_sessions = data
        elif isinstance(data, dict):
            page_sessions = (
                data.get("sessions")
                or data.get("data")
                or data.get("results")
                or []
            )
        else:
            page_sessions = []

        sessions.extend(page_sessions)
        print(f"  [page {page}] {len(page_sessions)} sessions (total: {len(sessions)})")

        if page == 1 and not page_sessions:
            print(f"  [debug] Full response (truncated):\n{json.dumps(data, indent=2)[:2000]}")

        # Pagination: stop when we get fewer results than page_size
        if len(page_sessions) < PAGE_SIZE:
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
    feed_path = feeds_dir / "fortinet_ips.txt"

    # Load existing metadata
    metadata: dict = {}
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text())
        except Exception:
            metadata = {}

    now_str = fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff = fetch_ts - timedelta(days=FEED_RETENTION_DAYS)

    # Extract source IPs from sessions — try multiple field paths
    new_ips: set[str] = set()
    for session in sessions:
        ip = None
        if isinstance(session, dict):
            ip = (
                (session.get("source") or {}).get("ip")
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
    window_start: datetime,
    window_end: datetime,
    fetch_ts: datetime,
    duration: float,
    error: str | None,
    feed_ip_count: int,
) -> None:
    """Write session data file (if sessions found) and run log (always)."""
    ts_str = fetch_ts.strftime("%Y-%m-%d_%H%M")
    repo_root = Path(__file__).parent.parent

    data_dir = repo_root / "data"
    runs_dir = repo_root / "runs"
    data_dir.mkdir(exist_ok=True)
    runs_dir.mkdir(exist_ok=True)

    # Run log — always written
    run_log = {
        "timestamp": fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensor_id": sensor_id,
        "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_window_end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sessions_found": len(sessions),
        "feed_ip_count": feed_ip_count,
        "duration_seconds": round(duration, 2),
        "error": error,
    }
    run_log_path = runs_dir / f"{ts_str}_run_log.json"
    run_log_path.write_text(json.dumps(run_log, indent=2))
    print(f"[+] Run log written: {run_log_path.name}")

    # Session data — only if we have sessions
    if sessions:
        data_payload = {
            "fetch_timestamp": fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sensor_id": sensor_id,
            "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "time_window_end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_count": len(sessions),
            "sessions": sessions,
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
    api_key = get_env("GREYNOISE_API_KEY")
    sensor_id = get_env("SENSOR_ID")

    now = datetime.now(timezone.utc)
    repo_root = Path(__file__).parent.parent

    # Determine time window
    # On first run (no ip_metadata.json): fetch last 30 days to bootstrap the feed
    # Otherwise: use env vars from scheduler, or default to last 6 hours
    window_start_str = os.environ.get("TIME_WINDOW_START")
    window_end_str = os.environ.get("TIME_WINDOW_END")

    bootstrap = is_first_run(repo_root)

    if bootstrap:
        print("[*] First run detected — bootstrapping feed with last 30 days of data")
        window_end = now
        window_start = now - timedelta(days=30)
    elif window_start_str and window_end_str:
        window_start = datetime.fromisoformat(window_start_str.replace("Z", "+00:00"))
        window_end = datetime.fromisoformat(window_end_str.replace("Z", "+00:00"))
    else:
        window_end = now
        window_start = now - timedelta(hours=6)

    print(f"[*] GreyNoise Swarm — session fetch")
    print(f"    Sensor   : {sensor_id}")
    print(f"    Window   : {window_start.strftime('%Y-%m-%dT%H:%M:%SZ')} → "
          f"{window_end.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"    Bootstrap: {bootstrap}")
    print(f"    Endpoint : {SESSIONS_URL}")

    start_time = time.monotonic()
    error = None
    sessions = []
    feed_ip_count = 0

    try:
        print("[*] Fetching sessions...")
        sessions = fetch_sessions(api_key, sensor_id, window_start, window_end)

        print("[*] Updating threat feed...")
        feed_ip_count = update_threat_feed(sessions, repo_root, now)

    except SystemExit:
        raise
    except Exception as exc:
        error = str(exc)
        print(f"[error] Unexpected error: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    duration = time.monotonic() - start_time
    write_outputs(
        sessions, sensor_id, window_start, window_end, now, duration, error, feed_ip_count
    )

    print(f"[*] Done in {duration:.1f}s — {len(sessions)} sessions, "
          f"{feed_ip_count} IPs in feed.")


if __name__ == "__main__":
    main()
