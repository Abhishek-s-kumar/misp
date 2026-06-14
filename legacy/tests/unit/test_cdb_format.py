"""Tests for CDB list writer output format."""
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
from collector.base import RawIOC
from ioc_validators.ioc_validator import ValidatedIOC

def make_raw(ioc_type="ip-src", value="1.2.3.4"):
    return RawIOC(
        ioc_type=ioc_type,
        value=value,
        event_id=1,
        event_uuid="test-uuid",
        timestamp=datetime.now(timezone.utc),
        tags=[],
        to_ids=True
    )

def write_cdb_list(entries: list[ValidatedIOC], output_path: Path) -> None:
    """Write a Wazuh CDB list file from validated IOC entries."""
    lines = sorted(set(f"{ioc.value}:malicious" for ioc in entries))
    output_path.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")


def test_cdb_format_correct_key_value(tmp_path):
    iocs = [
        ValidatedIOC("ip", "1.2.3.4", make_raw()),
        ValidatedIOC("ip", "5.6.7.8", make_raw(value="5.6.7.8"))
    ]
    out = tmp_path / "misp_ips"
    write_cdb_list(iocs, out)

    content = out.read_text(encoding="utf-8")
    assert "1.2.3.4:malicious" in content
    assert "5.6.7.8:malicious" in content


def test_cdb_format_sorted(tmp_path):
    iocs = [
        ValidatedIOC("ip", "9.9.9.9", make_raw(value="9.9.9.9")),
        ValidatedIOC("ip", "1.1.1.1", make_raw(value="1.1.1.1")),
        ValidatedIOC("ip", "5.5.5.5", make_raw(value="5.5.5.5")),
    ]
    out = tmp_path / "misp_ips"
    write_cdb_list(iocs, out)

    lines = [l for l in out.read_text(encoding="utf-8").strip().splitlines() if l]
    assert lines == sorted(lines)


def test_cdb_format_no_duplicates(tmp_path):
    iocs = [
        ValidatedIOC("ip", "1.1.1.1", make_raw(value="1.1.1.1")),
        ValidatedIOC("ip", "1.1.1.1", make_raw(value="1.1.1.1")),
        ValidatedIOC("ip", "1.1.1.1", make_raw(value="1.1.1.1")),
    ]
    out = tmp_path / "misp_ips"
    write_cdb_list(iocs, out)

    lines = [l for l in out.read_text(encoding="utf-8").strip().splitlines() if l]
    assert len(lines) == 1


def test_cdb_format_ends_with_newline(tmp_path):
    iocs = [ValidatedIOC("ip", "1.2.3.4", make_raw())]
    out = tmp_path / "misp_ips"
    write_cdb_list(iocs, out)

    content = out.read_text(encoding="utf-8")
    assert content.endswith("\n")


def test_cdb_format_empty_list(tmp_path):
    out = tmp_path / "misp_ips"
    write_cdb_list([], out)
    content = out.read_text(encoding="utf-8")
    assert content == ""
