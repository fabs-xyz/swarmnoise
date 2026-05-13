import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import fetch_sessions
import pytest
import requests
import requests_mock as rm_module


def test_v3_fetch_page_success(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v3/sessions",
        json={
            "sessions": [
                {"source": {"ip": "192.0.2.1"}, "classification": "malicious"},
                {"source": {"ip": "192.0.2.2"}, "classification": "suspicious"},
            ],
            "total": 2,
        },
    )
    sessions, total = fetch_sessions._v3_fetch_page(
        "test-key",
        datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 10, 6, 0, 0, tzinfo=timezone.utc),
        "classification:malicious",
        1,
    )
    assert total == 2
    assert len(sessions) == 2


def test_v3_fetch_page_empty(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v3/sessions",
        json={"sessions": [], "total": 0},
    )
    sessions, total = fetch_sessions._v3_fetch_page(
        "test-key",
        datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 5, 10, 6, 0, 0, tzinfo=timezone.utc),
        "classification:malicious",
        1,
    )
    assert total == 0
    assert sessions == []


def test_v3_fetch_page_retry_on_429(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v3/sessions",
        [
            {"status_code": 429, "text": "rate limited"},
            {"status_code": 429, "text": "rate limited"},
            {"json": {"sessions": [{"source": {"ip": "192.0.2.1"}}], "total": 1}},
        ],
    )
    with patch("fetch_sessions.time.sleep"):
        sessions, total = fetch_sessions._v3_fetch_page(
            "test-key",
            datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 5, 10, 6, 0, 0, tzinfo=timezone.utc),
            "classification:malicious",
            1,
            retries=3,
        )
    assert len(sessions) == 1


def test_v3_fetch_page_exhausted_retries(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v3/sessions",
        [{"status_code": 429, "text": "rate limited"}] * 10,
    )
    with patch("fetch_sessions.time.sleep"):
        sessions, total = fetch_sessions._v3_fetch_page(
            "test-key",
            datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 5, 10, 6, 0, 0, tzinfo=timezone.utc),
            "classification:malicious",
            1,
            retries=3,
        )
    assert sessions == []
    assert total == 0


def test_fetch_page_401_exits(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
        status_code=401,
        text="Unauthorized",
    )
    with pytest.raises(fetch_sessions.APIError) as exc_info:
        fetch_sessions._fetch_page(
            "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
            {"key": "bad-key"},
            {},
            1,
        )
    assert exc_info.value.status_code == 401


def test_fetch_page_403_exits(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
        status_code=403,
        text="Forbidden",
    )
    with pytest.raises(fetch_sessions.APIError) as exc_info:
        fetch_sessions._fetch_page(
            "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
            {"key": "bad-key"},
            {},
            1,
        )
    assert exc_info.value.status_code == 403


def test_fetch_page_transient_retry(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
        status_code=500,
        text="server error",
    )
    import pytest
    with pytest.raises(requests.HTTPError):
        fetch_sessions._fetch_page(
            "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
            {"key": "test-key"},
            {},
            1,
        )


def test_fetch_sessions_chunking(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v1/workspaces/test-ws/sensors/activity",
        json=[{"source_ip": "192.0.2.1"}],
    )
    start = datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 5, 10, 2, 0, 0, tzinfo=timezone.utc)
    with patch("fetch_sessions.time.sleep"):
        sessions = fetch_sessions.fetch_sessions("key", "test-ws", start, end)
    assert len(sessions) == 4


def test_fetch_filtered_sessions_chunking(requests_mock):
    requests_mock.get(
        "https://api.greynoise.io/v3/sessions",
        json={"sessions": [{"source": {"ip": "192.0.2.1"}}], "total": 1},
    )
    start = datetime(2026, 5, 10, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 5, 10, 12, 0, 0, tzinfo=timezone.utc)
    with patch("fetch_sessions.time.sleep"):
        sessions = fetch_sessions.fetch_filtered_sessions("key", start, end)
    assert len(sessions) == 2


def test_get_env_missing():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(fetch_sessions.ConfigError):
            fetch_sessions.get_env("MISSING_VAR")


def test_get_env_present():
    with patch.dict("os.environ", {"TEST_VAR": "hello"}):
        assert fetch_sessions.get_env("TEST_VAR") == "hello"


def test_parse_sensor_ids_comma_separated():
    with patch.dict("os.environ", {"SENSOR_IDS": "uuid1:berlin,uuid2:tokyo"}, clear=False):
        result = fetch_sessions.parse_sensor_ids()
    assert result == {"uuid1": "berlin", "uuid2": "tokyo"}


def test_parse_sensor_ids_fallback():
    with patch.dict("os.environ", {"SENSOR_ID": "single-uuid"}, clear=False):
        with patch.dict("os.environ", {"SENSOR_IDS": ""}, clear=False):
            result = fetch_sessions.parse_sensor_ids()
    assert result == {"single-uuid": "default"}


def test_parse_sensor_ids_missing():
    with patch.dict("os.environ", {"SENSOR_IDS": "", "SENSOR_ID": ""}, clear=False):
        with pytest.raises(fetch_sessions.ConfigError):
            fetch_sessions.parse_sensor_ids()


def test_extract_sensor_id_variants():
    assert fetch_sessions._extract_sensor_id({"sensor_id": "s1"}) == "s1"
    assert fetch_sessions._extract_sensor_id({"sensorId": "s2"}) == "s2"
    assert fetch_sessions._extract_sensor_id({"sensor": {"id": "s3"}}) == "s3"
    assert fetch_sessions._extract_sensor_id({"sensor": {"_id": "s4"}}) == "s4"
    assert fetch_sessions._extract_sensor_id({"sensorIdStr": "s5"}) == "s5"
    assert fetch_sessions._extract_sensor_id({"sensor_id_str": "s6"}) == "s6"
    assert fetch_sessions._extract_sensor_id({}) is None


def test_is_first_run_true(repo_root):
    assert fetch_sessions.is_first_run(repo_root) is True


def test_is_first_run_false(repo_root):
    (repo_root / "feeds" / "ip_metadata.json").write_text("{}")
    assert fetch_sessions.is_first_run(repo_root) is False
