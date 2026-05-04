#!/usr/bin/env python3
"""
fetch_sessions.py

Queries the GreyNoise Project Swarm Session API for all sessions observed
by the configured sensor. Writes session data to data/, a run log to runs/,
and maintains a rolling 30-day FortiGate-ready threat feed in feeds/.

Environment variables required:
  GREYNOISE_API_KEY  — GreyNoise API key
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
# Configuration
# NOTE: If you get a 404, find the correct endpoint by inspecting the
# Network tab in browser DevTools while using the Session Explorer UI at
# viz.greynoise.io → Observe → Explore. Update SWARM_API_BASE accordingly.
# ---------------------------------------------------------------------------
SWARM_API_BASE = "https://api.greynoise.io"
SESSIONS_ENDPOINT = f"{SWARM_API_BASE}/v1/workspaces/{{workspace_id}}/sessions/search"
WORKSPACE_ENDPOINT = f"{SWARM_API_BASE}/v1/workspaces"

PAGE_SIZE = 1000
FEED_RETENTION_DAYS = 30


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[error] Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def get_workspace_id(api_key: str) -> str:
    """Fetch the workspace ID associated with the current API key."""
    headers = {
        "key": api_key,
        "Accept": "application/json",
    }
    try:
        resp = requests.get(WORKSPACE_ENDPOINT, headers=headers, timeout=30)

        print(f"  [workspace] HTTP {resp.status_code}")

        if resp.status_code == 404:
            print(
                "[error] Workspace endpoint returned 404. The API endpoint may have changed.\n"
                "        Check the README for instructions on finding the correct endpoint.\n"
                f"        Tried: GET {WORKSPACE_ENDPOINT}\n"
                f"        Response body: {resp.text[:500]}",
                file=sys.stderr,
            )
            sys.exit(1)

        if resp.status_code == 401:
            print(
                "[error] Authentication failed (401). Check your GREYNOISE_API_KEY.\n"
                f"        Response body: {resp.text[:500]}",
                file=sys.stderr,
            )
            sys.exit(1)

        resp.raise_for_status()
        data = resp.json()
        print(f"  [workspace] Response keys: {list(data.keys())}")

        # Handle different response shapes
        workspaces = data.get("workspaces") or data.get("data") or []
        if workspaces and isinstance(workspaces, list):
            return workspaces[0]["id"]
        if "id" in data:
            return data["id"]

        print(
            f"[error] Could not extract workspace ID from response.\n"
            f"        Full response: {json.dumps(data, indent=2)[:1000]}",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.RequestException as exc:
        print(f"[error] Failed to fetch workspace: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_sessions(
    api_key: str,
    workspace_id: str,
    sensor_id: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """Fetch all sessions for the sensor within the time window."""
    headers = {
        "key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # All sessions from this sensor — no profile filter needed since the
    # sensor exclusively runs the Fortinet profile
    query = f"gnMetadata.sensor.id:{sensor_id}"

    endpoint = SESSIONS_ENDPOINT.format(workspace_id=workspace_id)
    print(f"  [fetch] Endpoint: POST {endpoint}")
    print(f"  [fetch] Query: {query}")

    sessions = []
    scroll = None
    page = 0

    while True:
        page += 1
        payload = {
            "query": query,
            "size": PAGE_SIZE,
            "start_time": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if scroll:
            payload["scroll"] = scroll

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=60)

            print(f"  [page {page}] HTTP {resp.status_code}")

            if resp.status_code == 404:
                print(
                    "[error] Sessions endpoint returned 404.\n"
                    "        The Swarm session API endpoint URL may differ from what we expect.\n"
                    "        To find the correct URL:\n"
                    "          1. Log into viz.greynoise.io\n"
                    "          2. Open DevTools → Network tab\n"
                    "          3. Go to Observe → Explore and run a search\n"
                    "          4. Find the API call and copy the URL\n"
                    "          5. Update SWARM_API_BASE in this script\n"
                    f"        Tried: POST {endpoint}\n"
                    f"        Response body: {resp.text[:500]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if resp.status_code == 401:
                print(
                    "[error] Authentication failed (401). Check your GREYNOISE_API_KEY.\n"
                    f"        Response body: {resp.text[:500]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if not resp.ok:
                print(
                    f"[error] Unexpected HTTP {resp.status_code} on page {page}.\n"
                    f"        Response body: {resp.text[:1000]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            data = resp.json()

        except requests.RequestException as exc:
            print(f"[error] Request failed on page {page}: {exc}", file=sys.stderr)
            sys.exit(1)

        page_sessions = data.get("data") or data.get("sessions") or []
        sessions.extend(page_sessions)

        print(f"  [page {page}] {len(page_sessions)} sessions (total: {len(sessions)})")

        # Print response structure on first page to help with debugging
        if page == 1 and not page_sessions:
            print(f"  [debug] Response keys: {list(data.keys())}")
            print(f"  [debug] Full response (truncated): {json.dumps(data, indent=2)[:2000]}")

        # Pagination via scroll token
        meta = data.get("request_metadata") or data.get("metadata") or {}
        complete = meta.get("complete", True)
        scroll = meta.get("scroll")

        if complete or not scroll or not page_sessions:
            break

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

    # Extract source IPs from sessions
    new_ips: set[str] = set()
    for session in sessions:
        # Try multiple possible field paths for source IP
        ip = (
            (session.get("source") or {}).get("ip")
            or session.get("source.ip")
            or session.get("srcIp")
            or session.get("src_ip")
        )
        if ip and isinstance(ip, str) and ip.strip():
            new_ips.add(ip.strip())

    print(f"  [feed] {len(new_ips)} unique source IPs extracted from sessions")

    # Update metadata — set first_seen on new IPs, update last_seen on all
    new_count = 0
    for ip in new_ips:
        if ip not in metadata:
            metadata[ip] = {
                "first_seen": now_str,
                "last_seen": now_str,
            }
            new_count += 1
        else:
            metadata[ip]["last_seen"] = now_str

    # Prune IPs outside the 30-day retention window
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

    start_time = time.monotonic()
    error = None
    sessions = []
    feed_ip_count = 0

    try:
        print("[*] Resolving workspace ID...")
        workspace_id = get_workspace_id(api_key)
        print(f"    Workspace: {workspace_id}")

        print("[*] Fetching sessions...")
        sessions = fetch_sessions(
            api_key, workspace_id, sensor_id, window_start, window_end
        )

        print(f"[*] Updating threat feed...")
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
