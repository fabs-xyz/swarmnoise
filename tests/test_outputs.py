import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import fetch_sessions

from .conftest import NOW_STR


def _write_outputs_with_repo(repo_root, **kwargs):
    with patch.object(fetch_sessions.Path, "parent", new_callable=lambda: property(lambda self: type(self)(str(repo_root)) if str(self).endswith("scripts") else self.parent)):
        pass
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(**kwargs)


def test_write_outputs_creates_run_log(repo_root, now):
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    (repo_root / "scripts").mkdir(exist_ok=True)
    (repo_root / "scripts" / "fetch_sessions.py").write_text("")
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(
            sessions=[{"source_ip": "192.0.2.1"}],
            sensor_map={"s1": "berlin"},
            workspace_id="ws-1",
            window_start=now - timedelta(hours=6),
            window_end=now,
            fetch_ts=now,
            duration=5.2,
            error=None,
            feed_ip_count=42,
        )
    logs = list((repo_root / "runs").glob("*_run_log.json"))
    assert len(logs) == 1
    log = json.loads(logs[0].read_text())
    assert log["sessions_found"] == 1
    assert log["feed_ip_count"] == 42
    assert log["duration_seconds"] == 5.2
    assert log["error"] is None


def test_write_outputs_creates_data_file(repo_root, now):
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    (repo_root / "scripts").mkdir(exist_ok=True)
    (repo_root / "scripts" / "fetch_sessions.py").write_text("")
    sessions = [{"source_ip": "192.0.2.1"}]
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(
            sessions=sessions,
            sensor_map={"s1": "berlin"},
            workspace_id="ws-1",
            window_start=now - timedelta(hours=6),
            window_end=now,
            fetch_ts=now,
            duration=1.0,
            error=None,
            feed_ip_count=1,
        )
    data_files = list((repo_root / "data").glob("*.json"))
    assert len(data_files) == 1
    payload = json.loads(data_files[0].read_text())
    assert payload["session_count"] == 1
    assert payload["workspace_id"] == "ws-1"


def test_write_outputs_no_data_file_on_empty_sessions(repo_root, now):
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    (repo_root / "scripts").mkdir(exist_ok=True)
    (repo_root / "scripts" / "fetch_sessions.py").write_text("")
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(
            sessions=[],
            sensor_map={"s1": "berlin"},
            workspace_id="ws-1",
            window_start=now - timedelta(hours=6),
            window_end=now,
            fetch_ts=now,
            duration=0.5,
            error=None,
            feed_ip_count=0,
        )
    data_files = list((repo_root / "data").glob("*.json"))
    assert len(data_files) == 0


def test_write_outputs_no_data_file_on_bootstrap(repo_root, now):
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    (repo_root / "scripts").mkdir(exist_ok=True)
    (repo_root / "scripts" / "fetch_sessions.py").write_text("")
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(
            sessions=[{"source_ip": "192.0.2.1"}],
            sensor_map={"s1": "berlin"},
            workspace_id="ws-1",
            window_start=now - timedelta(days=29),
            window_end=now,
            fetch_ts=now,
            duration=10.0,
            error=None,
            feed_ip_count=100,
            bootstrap=True,
        )
    data_files = list((repo_root / "data").glob("*.json"))
    assert len(data_files) == 0


def test_write_outputs_records_error(repo_root, now):
    fake_file = str(repo_root / "scripts" / "fetch_sessions.py")
    (repo_root / "scripts").mkdir(exist_ok=True)
    (repo_root / "scripts" / "fetch_sessions.py").write_text("")
    with patch("fetch_sessions.__file__", fake_file):
        fetch_sessions.write_outputs(
            sessions=[],
            sensor_map={"s1": "berlin"},
            workspace_id="ws-1",
            window_start=now - timedelta(hours=6),
            window_end=now,
            fetch_ts=now,
            duration=0.1,
            error="HTTP 500: server error",
            feed_ip_count=0,
        )
    logs = list((repo_root / "runs").glob("*_run_log.json"))
    log = json.loads(logs[0].read_text())
    assert log["error"] == "HTTP 500: server error"
