import json

import fetch_sessions


def test_high_confidence_malicious(repo_root):
    meta = {
        "192.0.2.1": {
            "classification": "malicious",
            "multi_sensor": False,
        },
        "192.0.2.2": {
            "classification": "suspicious",
            "multi_sensor": False,
        },
        "192.0.2.3": {
            "classification": "malicious",
            "multi_sensor": True,
        },
    }
    (repo_root / "feeds" / "filtered_metadata.json").write_text(json.dumps(meta))
    count = fetch_sessions.update_high_confidence_feed(repo_root)
    assert count == 2
    feed = (repo_root / "feeds" / "threat_feed_high_confidence.txt").read_text()
    ips = feed.strip().split("\n")
    assert "192.0.2.1" in ips
    assert "192.0.2.3" in ips
    assert "192.0.2.2" not in ips


def test_high_confidence_multi_sensor(repo_root):
    meta = {
        "192.0.2.1": {
            "classification": "suspicious",
            "multi_sensor": True,
        },
    }
    (repo_root / "feeds" / "filtered_metadata.json").write_text(json.dumps(meta))
    count = fetch_sessions.update_high_confidence_feed(repo_root)
    assert count == 1


def test_high_confidence_no_metadata_file(repo_root):
    count = fetch_sessions.update_high_confidence_feed(repo_root)
    assert count == 0
    assert (repo_root / "feeds" / "threat_feed_high_confidence.txt").read_text() == ""


def test_high_confidence_empty_metadata(repo_root):
    (repo_root / "feeds" / "filtered_metadata.json").write_text("{}")
    count = fetch_sessions.update_high_confidence_feed(repo_root)
    assert count == 0


def test_high_confidence_corrupt_metadata(repo_root):
    (repo_root / "feeds" / "filtered_metadata.json").write_text("NOT JSON")
    count = fetch_sessions.update_high_confidence_feed(repo_root)
    assert count == 0


def test_high_confidence_sorted_output(repo_root):
    meta = {
        "192.0.2.3": {"classification": "malicious", "multi_sensor": False},
        "192.0.2.1": {"classification": "malicious", "multi_sensor": False},
        "192.0.2.2": {"classification": "malicious", "multi_sensor": False},
    }
    (repo_root / "feeds" / "filtered_metadata.json").write_text(json.dumps(meta))
    fetch_sessions.update_high_confidence_feed(repo_root)
    ips = (repo_root / "feeds" / "threat_feed_high_confidence.txt").read_text().strip().split("\n")
    assert ips == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
