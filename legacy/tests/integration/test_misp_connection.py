"""Integration test: PyMISPProvider with a mocked PyMISP client."""
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import pytest
from collector.base import RawIOC


MOCK_ATTRIBUTE = {
    "type": "ip-src",
    "value": "185.100.87.10",
    "event_id": "1001",
    "Event": {"uuid": "f290b83e-1175-47e2-824c-1e247492c10b"},
    "timestamp": "1718352000",
    "Tag": [{"name": "tlp:white"}],
    "to_ids": True
}


@patch.dict("os.environ", {
    "MISP_URL": "https://misp.test.local",
    "MISP_API_KEY": "test-api-key",
    "MISP_VERIFY_SSL": "false"
})
@patch("collector.pymisp_provider.PyMISP")
def test_pymisp_provider_fetch_iocs(mock_pymisp_cls):
    """PyMISPProvider.fetch_iocs should normalize MISP attributes into RawIOC objects."""
    from collector.pymisp_provider import PyMISPProvider

    mock_client = MagicMock()
    mock_client.search.return_value = {"Attribute": [MOCK_ATTRIBUTE]}
    mock_pymisp_cls.return_value = mock_client

    provider = PyMISPProvider()
    results = provider.fetch_iocs(
        ioc_types=["ip-src"],
        tags=["tlp:white"]
    )

    assert len(results) == 1
    ioc = results[0]
    assert isinstance(ioc, RawIOC)
    assert ioc.ioc_type == "ip-src"
    assert ioc.value == "185.100.87.10"
    assert ioc.event_id == 1001
    assert ioc.event_uuid == "f290b83e-1175-47e2-824c-1e247492c10b"
    assert "tlp:white" in ioc.tags
    assert ioc.to_ids is True


@patch.dict("os.environ", {
    "MISP_URL": "https://misp.test.local",
    "MISP_API_KEY": "test-api-key",
    "MISP_VERIFY_SSL": "false"
})
@patch("collector.pymisp_provider.PyMISP")
def test_pymisp_provider_incremental_uses_timestamp(mock_pymisp_cls):
    """PyMISPProvider.fetch_iocs should pass timestamp= when since is provided."""
    from collector.pymisp_provider import PyMISPProvider

    mock_client = MagicMock()
    mock_client.search.return_value = {"Attribute": []}
    mock_pymisp_cls.return_value = mock_client

    provider = PyMISPProvider()
    since = datetime(2026, 6, 14, 9, 0, 0, tzinfo=timezone.utc)
    provider.fetch_iocs(ioc_types=["ip-src"], tags=[], since=since)

    call_kwargs = mock_client.search.call_args.kwargs
    assert "timestamp" in call_kwargs
    assert call_kwargs["timestamp"] == int(since.timestamp())


@patch.dict("os.environ", {
    "MISP_URL": "https://misp.test.local",
    "MISP_API_KEY": "test-api-key",
    "MISP_VERIFY_SSL": "false"
})
@patch("collector.pymisp_provider.PyMISP")
def test_pymisp_provider_empty_results(mock_pymisp_cls):
    """PyMISPProvider.fetch_iocs should return empty list on empty search results."""
    from collector.pymisp_provider import PyMISPProvider

    mock_client = MagicMock()
    mock_client.search.return_value = {"Attribute": []}
    mock_pymisp_cls.return_value = mock_client

    provider = PyMISPProvider()
    results = provider.fetch_iocs(ioc_types=["ip-src"], tags=[])
    assert results == []
