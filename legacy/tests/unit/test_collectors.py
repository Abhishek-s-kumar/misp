"""Tests for MISPIOCCollector with the MISPProvider abstraction."""
import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from pathlib import Path
import pytest
from collector.base import RawIOC, MISPProvider
from collector.misp_iocs import MISPIOCCollector


def make_raw_ioc(ioc_type="ip-src", value="8.8.8.8") -> RawIOC:
    return RawIOC(
        ioc_type=ioc_type,
        value=value,
        event_id=100,
        event_uuid="event-uuid-123",
        timestamp=datetime(2026, 6, 14, 9, 0, 0, tzinfo=timezone.utc),
        tags=["tlp:white"],
        to_ids=True
    )


def test_collector_full_pull(tmp_path):
    """Collector should call fetch_iocs with since=None on full_pull=True."""
    mock_provider = MagicMock(spec=MISPProvider)
    mock_provider.fetch_iocs.return_value = [make_raw_ioc()]

    state_file = tmp_path / "sync_state.json"
    collector = MISPIOCCollector(provider=mock_provider, state_file=state_file)
    iocs = collector.pull(ioc_types=["ip-src"], tags=["tlp:white"], full_pull=True)

    mock_provider.fetch_iocs.assert_called_once_with(
        ioc_types=["ip-src"],
        tags=["tlp:white"],
        since=None
    )
    assert len(iocs) == 1
    assert iocs[0].value == "8.8.8.8"
    assert state_file.exists()
    with open(state_file) as f:
        data = json.load(f)
    assert "last_sync_time" in data


def test_collector_incremental_pull(tmp_path):
    """Collector should call fetch_iocs with since=<last_sync> on incremental pull."""
    mock_provider = MagicMock(spec=MISPProvider)
    mock_provider.fetch_iocs.return_value = []

    state_file = tmp_path / "sync_state.json"
    saved_time = datetime(2026, 6, 14, 9, 0, 0, tzinfo=timezone.utc)
    state_file.write_text(json.dumps({"last_sync_time": saved_time.isoformat()}))

    collector = MISPIOCCollector(provider=mock_provider, state_file=state_file)
    collector.pull(ioc_types=["ip-src"], tags=["tlp:white"], full_pull=False)

    call_kwargs = mock_provider.fetch_iocs.call_args.kwargs
    assert call_kwargs["since"] == saved_time


def test_collector_state_saved_after_pull(tmp_path):
    """State file should be updated with new timestamp after each pull."""
    mock_provider = MagicMock(spec=MISPProvider)
    mock_provider.fetch_iocs.return_value = []

    state_file = tmp_path / "sync_state.json"
    collector = MISPIOCCollector(provider=mock_provider, state_file=state_file)
    collector.pull(ioc_types=["ip-src"], tags=[], full_pull=True)

    assert state_file.exists()
    with open(state_file) as f:
        data = json.load(f)
    assert "last_sync_time" in data


def test_collector_missing_state_file_treated_as_full_pull(tmp_path):
    """If no state file exists, since should be None (same as full pull)."""
    mock_provider = MagicMock(spec=MISPProvider)
    mock_provider.fetch_iocs.return_value = []

    state_file = tmp_path / "nonexistent_state.json"
    collector = MISPIOCCollector(provider=mock_provider, state_file=state_file)
    collector.pull(ioc_types=["ip-src"], tags=[], full_pull=False)

    call_kwargs = mock_provider.fetch_iocs.call_args.kwargs
    assert call_kwargs["since"] is None
