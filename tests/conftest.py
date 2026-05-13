import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import fetch_sessions
import pytest


@pytest.fixture
def repo_root(tmp_path):
    for d in ("feeds", "runs", "state", "data"):
        (tmp_path / d).mkdir(exist_ok=True)
    return tmp_path


@pytest.fixture
def now():
    return datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def cutoff(now):
    return now - timedelta(days=30)


NOW_STR = "2026-05-10T12:00:00Z"


def _make_v1_session(ip, sensor_id="s1", ts="2026-05-10T10:00:00Z"):
    return {
        "source_ip": ip,
        "sensor_id": sensor_id,
        "timestamp": ts,
    }


def _make_v3_session(ip, classification="malicious", sensor_id="s1"):
    return {
        "source": {"ip": ip},
        "sensor": {"id": sensor_id},
        "classification": classification,
        "sourceMetadata": {
            "country": "Germany",
            "country_code": "DE",
            "asn": "AS64496",
            "org": "Test ISP",
            "is_vpn": False,
            "is_tor": False,
            "is_bot": False,
            "rdns": "host.test.example.com",
        },
        "gnTagMetadata": [
            {"name": "Mirai", "category": "worm", "intention": "malicious", "cves": []},
        ],
        "protocol": ["tcp"],
        "destination": {"port": 23},
        "suricata": {"signature": ["sig-001"]},
    }


@pytest.fixture
def v1_sessions():
    return [
        _make_v1_session("192.0.2.1"),
        _make_v1_session("192.0.2.2"),
        _make_v1_session("192.0.2.3"),
        _make_v1_session("192.0.2.1"),
        _make_v1_session("198.51.100.1", sensor_id="s2"),
        _make_v1_session("203.0.113.5"),
    ]


@pytest.fixture
def v3_sessions():
    return [
        _make_v3_session("192.0.2.1", "malicious", "s1"),
        _make_v3_session("192.0.2.2", "suspicious", "s1"),
        _make_v3_session("198.51.100.1", "malicious", "s2"),
        _make_v3_session("203.0.113.5", "suspicious", "s1"),
    ]


@pytest.fixture
def sensor_map():
    return {"s1": "berlin", "s2": "tokyo"}


@pytest.fixture
def preseeded_metadata(repo_root):
    meta = {
        "192.0.2.100": {
            "first_seen": "2026-04-01T00:00:00Z",
            "last_seen": "2026-04-05T00:00:00Z",
            "seen_by": ["berlin"],
        },
    }
    (repo_root / "feeds" / "ip_metadata.json").write_text(json.dumps(meta))
    return meta
