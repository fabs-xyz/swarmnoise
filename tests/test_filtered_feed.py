import json

import fetch_sessions

from .conftest import NOW_STR, _make_v3_session


def test_filtered_feed_basic(repo_root, now, sensor_map):
    sessions = [
        _make_v3_session("192.0.2.1", "malicious", "s1"),
        _make_v3_session("198.51.100.1", "suspicious", "s2"),
    ]
    ip_meta = {
        "192.0.2.1": {"seen_by": ["berlin"]},
        "198.51.100.1": {"seen_by": ["tokyo"]},
    }
    count = fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=sensor_map, ip_metadata=ip_meta,
    )
    assert count == 2
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert "192.0.2.1" in meta
    assert "198.51.100.1" in meta


def test_filtered_metadata_fields(repo_root, now, sensor_map):
    sessions = [_make_v3_session("192.0.2.1", "malicious", "s1")]
    count = fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=sensor_map, ip_metadata={},
    )
    assert count == 1
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    entry = meta["192.0.2.1"]
    assert entry["classification"] == "malicious"
    assert entry["country_code"] == "DE"
    assert entry["asn"] == "AS64496"
    assert "Mirai" in entry["tags"]
    assert "worm" in entry["tag_categories"]
    assert "malicious" in entry["tag_intentions"]
    assert 23 in entry["destination_ports"]
    assert "tcp" in entry["protocols"]
    assert "sig-001" in entry["suricata_signatures"]
    assert entry["seen_by"] == ["berlin"]


def test_multi_sensor_flag(repo_root, now, sensor_map):
    sessions = [
        _make_v3_session("192.0.2.1", "malicious", "s1"),
    ]
    ip_meta = {
        "192.0.2.1": {"seen_by": ["berlin", "tokyo"]},
    }
    fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=sensor_map, ip_metadata=ip_meta,
    )
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert meta["192.0.2.1"]["multi_sensor"] is True


def test_multi_sensor_false_for_single(repo_root, now, sensor_map):
    sessions = [_make_v3_session("192.0.2.1", "malicious", "s1")]
    ip_meta = {"192.0.2.1": {"seen_by": ["berlin"]}}
    fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=sensor_map, ip_metadata=ip_meta,
    )
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert meta["192.0.2.1"]["multi_sensor"] is False


def test_cves_extracted(repo_root, now, sensor_map):
    sessions = [
        {
            "source": {"ip": "192.0.2.1"},
            "sensor": {"id": "s1"},
            "classification": "malicious",
            "sourceMetadata": {},
            "gnTagMetadata": [
                {
                    "name": "Apache Exploit",
                    "category": "activity",
                    "intention": "malicious",
                    "cves": ["CVE-2021-41773", "CVE-2021-42013"],
                },
            ],
            "protocol": ["tcp"],
            "destination": {"port": 80},
            "suricata": {"signature": []},
        },
    ]
    fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=sensor_map, ip_metadata={},
    )
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert sorted(meta["192.0.2.1"]["cves"]) == ["CVE-2021-41773", "CVE-2021-42013"]


def test_ports_merged_across_sessions(repo_root, now, sensor_map):
    s1 = _make_v3_session("192.0.2.1", "malicious", "s1")
    s1["destination"]["port"] = 23
    s2 = _make_v3_session("192.0.2.1", "malicious", "s1")
    s2["destination"]["port"] = 80
    fetch_sessions.update_filtered_feed(
        [s1, s2], repo_root, now, sensor_map=sensor_map, ip_metadata={},
    )
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert sorted(meta["192.0.2.1"]["destination_ports"]) == [23, 80]


def test_rolling_window_pruning_filtered(repo_root, now):
    old_ip = "192.0.2.200"
    existing = {
        old_ip: {
            "first_seen": "2026-04-01T00:00:00Z",
            "last_seen": "2026-04-05T00:00:00Z",
            "classification": "malicious",
            "tags": [],
            "tag_categories": [],
            "tag_intentions": [],
            "cves": [],
            "country": None,
            "country_code": None,
            "asn": None,
            "org": None,
            "is_vpn": False,
            "is_tor": False,
            "is_bot": False,
            "rdns": None,
            "destination_ports": [],
            "protocols": [],
            "suricata_signatures": [],
            "seen_by": [],
            "multi_sensor": False,
        },
    }
    (repo_root / "feeds" / "filtered_metadata.json").write_text(json.dumps(existing))
    sessions = [_make_v3_session("192.0.2.1", "malicious", "s1")]
    fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=None, ip_metadata={},
    )
    meta = json.loads((repo_root / "feeds" / "filtered_metadata.json").read_text())
    assert old_ip not in meta
    assert "192.0.2.1" in meta


def test_empty_filtered_sessions(repo_root, now):
    count = fetch_sessions.update_filtered_feed(
        [], repo_root, now, sensor_map=None, ip_metadata={},
    )
    assert count == 0


def test_non_dict_sessions_skipped(repo_root, now):
    sessions = ["bad", None, 42]
    count = fetch_sessions.update_filtered_feed(
        sessions, repo_root, now, sensor_map=None, ip_metadata={},
    )
    assert count == 0
