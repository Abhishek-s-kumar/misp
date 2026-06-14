"""Tests for MockMISPProvider."""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest
from collector.mock_provider import MockMISPProvider
from collector.base import RawIOC

FIXTURE_DATA = [
    {
        "ioc_type": "ip-src",
        "value": "185.100.87.10",
        "event_id": 1001,
        "event_uuid": "f290b83e-1175-47e2-824c-1e247492c10b",
        "timestamp": "2026-06-14T09:00:00+00:00",
        "tags": ["tlp:white"],
        "to_ids": True
    },
    {
        "ioc_type": "domain",
        "value": "evil-domain.ru",
        "event_id": 1002,
        "event_uuid": "762c2f7b-bb66-417f-ad66-f0803554471f",
        "timestamp": "2026-06-14T09:10:00+00:00",
        "tags": ["tlp:white"],
        "to_ids": True
    },
    {
        "ioc_type": "url",
        "value": "http://evil.com/payload.exe",
        "event_id": 1003,
        "event_uuid": "aabbccdd-eeff-1122-3344-556677889900",
        "timestamp": "2026-06-14T09:25:00+00:00",
        "tags": ["tlp:red"],
        "to_ids": True
    }
]


@pytest.fixture
def fixture_path(tmp_path):
    fixture_file = tmp_path / "mock_iocs.json"
    fixture_file.write_text(json.dumps(FIXTURE_DATA), encoding="utf-8")
    return fixture_file


def test_fetch_all_ioc_types(fixture_path):
    provider = MockMISPProvider(fixture_path=fixture_path)
    results = provider.fetch_iocs(
        ioc_types=["ip-src", "domain", "url"],
        tags=[]
    )
    assert len(results) == 3
    assert all(isinstance(r, RawIOC) for r in results)


def test_fetch_filters_by_ioc_type(fixture_path):
    provider = MockMISPProvider(fixture_path=fixture_path)
    results = provider.fetch_iocs(ioc_types=["domain"], tags=[])
    assert len(results) == 1
    assert results[0].value == "evil-domain.ru"


def test_fetch_filters_by_tag(fixture_path):
    provider = MockMISPProvider(fixture_path=fixture_path)
    results = provider.fetch_iocs(
        ioc_types=["ip-src", "domain", "url"],
        tags=["tlp:red"]
    )
    assert len(results) == 1
    assert results[0].value == "http://evil.com/payload.exe"


def test_fetch_incremental_since(fixture_path):
    provider = MockMISPProvider(fixture_path=fixture_path)
    since = datetime(2026, 6, 14, 9, 20, 0, tzinfo=timezone.utc)
    results = provider.fetch_iocs(
        ioc_types=["ip-src", "domain", "url"],
        tags=[],
        since=since
    )
    # Only items with timestamp > since should be returned
    assert len(results) == 1
    assert results[0].value == "http://evil.com/payload.exe"


def test_fixture_not_found_raises():
    provider = MockMISPProvider(fixture_path=Path("/nonexistent/path/mock_iocs.json"))
    with pytest.raises(FileNotFoundError):
        provider.fetch_iocs(ioc_types=["ip-src"], tags=[])
