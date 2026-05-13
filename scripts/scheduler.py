#!/usr/bin/env python3
"""
scheduler.py

Schedule logic for SwarmNoise's randomized daily fetch pattern.

Subcommands:
  evaluate  — Evaluate schedule and decide whether to fetch this tick.
  success   — Update state after a successful fetch.
  failure   — Record a fetch failure for retry at next tick.

Environment variables:
  TZ                 — Timezone for scheduling (default: UTC)
  GITHUB_EVENT_NAME  — Set by GitHub Actions (workflow_dispatch for manual runs)
  GITHUB_OUTPUT      — File path for writing step outputs
"""

import json
import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

STATE_DIR = os.environ.get("STATE_DIR", "state")
STATE_FILE = Path(STATE_DIR) / "today.json"

DEFAULT_TZ = "UTC"


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_FILE)


def _get_tz() -> ZoneInfo:
    tz_name = os.environ.get("TZ", DEFAULT_TZ).strip()
    if not tz_name:
        tz_name = DEFAULT_TZ
    return ZoneInfo(tz_name)


def _write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{key}={value}\n")


def cmd_evaluate() -> None:
    tz = _get_tz()
    now_utc = datetime.now(timezone.utc)
    now = now_utc.astimezone(tz)
    today_str = now.strftime("%Y-%m-%d")
    current_hour = now.hour

    state = _load_state()

    if state.get("date") != today_str:
        target_runs = random.randint(1, 10)
        scheduled_hours = sorted(random.sample(range(0, 24), min(target_runs, 24)))
        prev_last_fetch_end = state.get("last_fetch_end")
        state = {
            "date": today_str,
            "target_runs": target_runs,
            "completed_runs": 0,
            "scheduled_hours": scheduled_hours,
            "completed_hours": [],
            "last_fetch_end": prev_last_fetch_end,
            "last_run_failed": False,
        }
        _save_state(state)
        print(f"New day ({tz}) — scheduled {target_runs} runs at hours: {scheduled_hours}")

    is_manual = os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
    last_run_failed = state.get("last_run_failed", False)

    completed_hours = set(state.get("completed_hours", []))
    scheduled_hours = state.get("scheduled_hours", [])
    overdue_hours = [
        h for h in scheduled_hours
        if h <= current_hour and h not in completed_hours
    ]

    should_fetch = is_manual or last_run_failed or (
        bool(overdue_hours)
        and state.get("completed_runs", 0) < state.get("target_runs", 0)
    )

    if is_manual:
        print("Manual dispatch — bypassing schedule gate, fetch forced")
    elif last_run_failed:
        print(f"Last run failed — retrying this tick ({current_hour})")
    elif overdue_hours:
        print(f"Overdue scheduled hours detected: {overdue_hours} — triggering fetch")

    if should_fetch:
        if state.get("last_fetch_end"):
            window_start = state["last_fetch_end"]
        else:
            from datetime import timedelta
            window_start = (now_utc - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        window_end = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        window_start = ""
        window_end = ""

    _write_output("should_fetch", "true" if should_fetch else "false")
    _write_output("window_start", window_start)
    _write_output("window_end", window_end)
    _write_output("current_hour", str(current_hour))
    _write_output("target_runs", str(state.get("target_runs", 0)))
    _write_output("completed_runs", str(state.get("completed_runs", 0)))
    overdue_str = ",".join(str(h) for h in overdue_hours) if overdue_hours else ""
    _write_output("overdue_hours", overdue_str)

    if should_fetch:
        print(f"Fetch triggered for hour {current_hour} — window: {window_start} → {window_end}")
    else:
        scheduled = state.get("scheduled_hours", [])
        completed = state.get("completed_runs", 0)
        target = state.get("target_runs", 0)
        print(f"No fetch this hour (hour={current_hour}, scheduled={scheduled}, "
              f"completed={completed}/{target})")


def cmd_success() -> None:
    current_hour = int(os.environ.get("CURRENT_HOUR", "0"))
    overdue_str = os.environ.get("OVERDUE_HOURS", "")
    overdue_hours = [int(h) for h in overdue_str.split(",") if h.strip()]
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    state = _load_state()
    state["completed_runs"] += 1
    for h in overdue_hours:
        if h not in state["completed_hours"]:
            state["completed_hours"].append(h)
    if current_hour not in state["completed_hours"]:
        state["completed_hours"].append(current_hour)
    state["last_fetch_end"] = now_str
    state["last_run_failed"] = False
    _save_state(state)
    print(f"State updated — completed {state['completed_runs']}/{state['target_runs']} runs today")


def cmd_failure() -> None:
    state = _load_state()
    state["last_run_failed"] = True
    _save_state(state)
    print("Fetch failed — last_run_failed set to True, will retry next cron tick")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: scheduler.py <evaluate|success|failure>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "evaluate":
        cmd_evaluate()
    elif cmd == "success":
        cmd_success()
    elif cmd == "failure":
        cmd_failure()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
