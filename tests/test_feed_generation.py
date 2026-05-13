import json
from datetime import datetime, timedelta, timezone

import fetch_sessions

from .conftest import NOW_STR, _make_v1_session


def test_ip_extraction_source_ip(repo_root, now, sensor_map):
    sessions = [_make_v1_session("192.0.2.1"), _make_v1_session("192.0.2.2")]
    count, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=sensor_map,
    )
    assert count == 2
    assert "192.0.2.1" in meta
    assert "192.0.2.2" in meta


def test_ip_extraction_sensor_id_field(repo_root, now):
    sessions = [{"source_ip": "192.0.2.1", "sensorId": "s1"}]
    smap = {"s1": "berlin"}
    count, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=smap,
    )
    assert count == 1
    assert meta["192.0.2.1"]["seen_by"] == ["berlin"]


def test_ip_extraction_nested_sensor(repo_root, now):
    sessions = [{"source_ip": "192.0.2.1", "sensor": {"id": "s1"}}]
    smap = {"s1": "berlin"}
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=smap,
    )
    assert meta["192.0.2.1"]["seen_by"] == ["berlin"]


def test_ip_extraction_nested_sensor_underscore(repo_root, now):
    sessions = [{"source_ip": "192.0.2.1", "sensor": {"_id": "s1"}}]
    smap = {"s1": "berlin"}
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=smap,
    )
    assert meta["192.0.2.1"]["seen_by"] == ["berlin"]


def test_deduplication_same_ip(repo_root, now):
    sessions = [
        _make_v1_session("192.0.2.1"),
        _make_v1_session("192.0.2.1"),
        _make_v1_session("192.0.2.1"),
    ]
    count, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert count == 1
    assert "192.0.2.1" in meta


def test_deduplication_across_sensors(repo_root, now, sensor_map):
    sessions = [
        _make_v1_session("192.0.2.1", sensor_id="s1"),
        _make_v1_session("192.0.2.1", sensor_id="s2"),
    ]
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=sensor_map,
    )
    assert sorted(meta["192.0.2.1"]["seen_by"]) == ["berlin", "tokyo"]


def test_rolling_window_pruning(repo_root, now, preseeded_metadata):
    old_ip = "192.0.2.100"
    assert old_ip in preseeded_metadata
    sessions = [_make_v1_session("192.0.2.1")]
    count, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert old_ip not in meta
    assert "192.0.2.1" in meta


def test_recent_ip_not_pruned(repo_root, now):
    recent = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    existing = {
        "192.0.2.50": {
            "first_seen": recent,
            "last_seen": recent,
            "seen_by": [],
        },
    }
    (repo_root / "feeds" / "ip_metadata.json").write_text(json.dumps(existing))
    sessions = [_make_v1_session("192.0.2.1")]
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert "192.0.2.50" in meta
    assert "192.0.2.1" in meta


def test_empty_sessions(repo_root, now):
    count, meta = fetch_sessions.update_threat_feed(
        [], repo_root, now, sensor_map=None,
    )
    assert count == 0
    assert meta == {}


def test_empty_sessions_preserves_existing(repo_root, now):
    existing = {
        "192.0.2.1": {
            "first_seen": NOW_STR,
            "last_seen": NOW_STR,
            "seen_by": [],
        },
    }
    (repo_root / "feeds" / "ip_metadata.json").write_text(json.dumps(existing))
    count, meta = fetch_sessions.update_threat_feed(
        [], repo_root, now, sensor_map=None,
    )
    assert count == 1
    assert "192.0.2.1" in meta


def test_feed_file_written(repo_root, now):
    sessions = [_make_v1_session("192.0.2.2"), _make_v1_session("192.0.2.1")]
    fetch_sessions.update_threat_feed(sessions, repo_root, now, sensor_map=None)
    feed_text = (repo_root / "feeds" / "threat_feed.txt").read_text()
    lines = feed_text.strip().split("\n")
    assert lines == ["192.0.2.1", "192.0.2.2"]


def test_metadata_json_written(repo_root, now):
    sessions = [_make_v1_session("192.0.2.1")]
    fetch_sessions.update_threat_feed(sessions, repo_root, now, sensor_map=None)
    meta = json.loads((repo_root / "feeds" / "ip_metadata.json").read_text())
    assert "192.0.2.1" in meta
    assert meta["192.0.2.1"]["first_seen"] == NOW_STR
    assert meta["192.0.2.1"]["last_seen"] == NOW_STR


def test_non_dict_sessions_skipped(repo_root, now):
    sessions = ["not_a_dict", 42, None, _make_v1_session("192.0.2.1")]
    count, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert count == 1
    assert "192.0.2.1" in meta


def test_missing_ip_fields_skipped(repo_root, now):
    sessions = [{"foo": "bar"}, {"source_ip": ""}, {"source_ip": None}]
    count, _ = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert count == 0


def test_last_seen_updated(repo_root, now):
    existing = {
        "192.0.2.1": {
            "first_seen": "2026-04-01T00:00:00Z",
            "last_seen": "2026-04-01T00:00:00Z",
            "seen_by": [],
        },
    }
    (repo_root / "feeds" / "ip_metadata.json").write_text(json.dumps(existing))
    sessions = [_make_v1_session("192.0.2.1")]
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=None,
    )
    assert meta["192.0.2.1"]["last_seen"] == NOW_STR
    assert meta["192.0.2.1"]["first_seen"] == "2026-04-01T00:00:00Z"


def test_seen_by_merged_on_subsequent_run(repo_root, now, sensor_map):
    existing = {
        "192.0.2.1": {
            "first_seen": NOW_STR,
            "last_seen": NOW_STR,
            "seen_by": ["berlin"],
        },
    }
    (repo_root / "feeds" / "ip_metadata.json").write_text(json.dumps(existing))
    sessions = [_make_v1_session("192.0.2.1", sensor_id="s2")]
    _, meta = fetch_sessions.update_threat_feed(
        sessions, repo_root, now, sensor_map=sensor_map,
    )
    assert sorted(meta["192.0.2.1"]["seen_by"]) == ["berlin", "tokyo"]
