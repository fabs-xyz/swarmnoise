import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "today.json"
    monkeypatch.setattr("scripts.scheduler.STATE_DIR", str(state_dir))
    monkeypatch.setattr("scripts.scheduler.STATE_FILE", state_file)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.setenv("TZ", "UTC")
    yield


@pytest.fixture()
def output_file(tmp_path):
    path = tmp_path / "gh_output"
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(path))
    yield path
    monkeypatch.undo()


def _read_state():
    import scripts.scheduler as sched
    if sched.STATE_FILE.exists():
        return json.loads(sched.STATE_FILE.read_text())
    return {}


def _read_outputs(output_file):
    if not output_file.exists():
        return {}
    out = {}
    for line in output_file.read_text().strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def test_evaluate_new_day(tmp_path, output_file):
    import scripts.scheduler as sched

    sched.cmd_evaluate()

    state = _read_state()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert state["date"] == today_str
    assert 1 <= state["target_runs"] <= 10
    assert state["completed_runs"] == 0
    assert state["last_run_failed"] is False

    outputs = _read_outputs(output_file)
    assert "should_fetch" in outputs


def test_evaluate_manual_dispatch(tmp_path, output_file, monkeypatch):
    import scripts.scheduler as sched

    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")

    state_dir = tmp_path / "state"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    (state_dir / "today.json").write_text(json.dumps({
        "date": today,
        "target_runs": 3,
        "completed_runs": 3,
        "scheduled_hours": [1, 2, 3],
        "completed_hours": [1, 2, 3],
        "last_fetch_end": "2026-01-01T00:00:00Z",
        "last_run_failed": False,
    }))

    with patch.object(sched, "_get_tz", return_value=sched.ZoneInfo("UTC")):
        sched.cmd_evaluate()

    outputs = _read_outputs(output_file)
    assert outputs["should_fetch"] == "true"


def test_evaluate_retry_after_failure(tmp_path, output_file, monkeypatch):
    import scripts.scheduler as sched

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state_dir = tmp_path / "state"
    (state_dir / "today.json").write_text(json.dumps({
        "date": today,
        "target_runs": 3,
        "completed_runs": 3,
        "scheduled_hours": [1, 2, 3],
        "completed_hours": [1, 2, 3],
        "last_fetch_end": "2026-01-01T00:00:00Z",
        "last_run_failed": True,
    }))

    with patch.object(sched, "_get_tz", return_value=sched.ZoneInfo("UTC")):
        sched.cmd_evaluate()

    outputs = _read_outputs(output_file)
    assert outputs["should_fetch"] == "true"


def test_evaluate_no_fetch_when_done(tmp_path, output_file):
    import scripts.scheduler as sched

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state_dir = tmp_path / "state"
    (state_dir / "today.json").write_text(json.dumps({
        "date": today,
        "target_runs": 1,
        "completed_runs": 1,
        "scheduled_hours": [0],
        "completed_hours": [0],
        "last_fetch_end": "2026-01-01T00:00:00Z",
        "last_run_failed": False,
    }))

    with patch.object(sched, "_get_tz", return_value=sched.ZoneInfo("UTC")):
        sched.cmd_evaluate()

    outputs = _read_outputs(output_file)
    assert outputs["should_fetch"] == "false"


def test_success_updates_state(tmp_path, monkeypatch):
    import scripts.scheduler as sched

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state_dir = tmp_path / "state"
    (state_dir / "today.json").write_text(json.dumps({
        "date": today,
        "target_runs": 5,
        "completed_runs": 0,
        "scheduled_hours": [8, 12, 16],
        "completed_hours": [],
        "last_fetch_end": None,
        "last_run_failed": False,
    }))

    monkeypatch.setenv("CURRENT_HOUR", "8")
    monkeypatch.setenv("OVERDUE_HOURS", "8")

    sched.cmd_success()

    state = _read_state()
    assert state["completed_runs"] == 1
    assert 8 in state["completed_hours"]
    assert state["last_fetch_end"] is not None
    assert state["last_run_failed"] is False


def test_failure_sets_flag(tmp_path):
    import scripts.scheduler as sched

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state_dir = tmp_path / "state"
    (state_dir / "today.json").write_text(json.dumps({
        "date": today,
        "target_runs": 5,
        "completed_runs": 0,
        "scheduled_hours": [8],
        "completed_hours": [],
        "last_fetch_end": None,
        "last_run_failed": False,
    }))

    sched.cmd_failure()

    state = _read_state()
    assert state["last_run_failed"] is True


def test_new_day_carries_last_fetch_end(tmp_path, output_file):
    import scripts.scheduler as sched

    state_dir = tmp_path / "state"
    (state_dir / "today.json").write_text(json.dumps({
        "date": "2020-01-01",
        "target_runs": 1,
        "completed_runs": 1,
        "scheduled_hours": [12],
        "completed_hours": [12],
        "last_fetch_end": "2020-01-01T12:00:00Z",
        "last_run_failed": False,
    }))

    with patch.object(sched, "_get_tz", return_value=sched.ZoneInfo("UTC")):
        sched.cmd_evaluate()

    state = _read_state()
    assert state["last_fetch_end"] == "2020-01-01T12:00:00Z"


def test_unknown_command(capsys):
    import scripts.scheduler as sched

    with pytest.raises(SystemExit):
        sched.main()
    with pytest.raises(SystemExit):
        import sys
        with patch.object(sys, "argv", ["scheduler.py", "bogus"]):
            sched.main()
