import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from collector.base import RawRule
from processors import (
    process_pending_rules,
    list_quarantined_rules,
    promote_quarantined_rule,
    reject_quarantined_rule,
)


def make_wazuh_rule(name="test_rule.xml", rid="999999", tags=None, desc="quarantine test rule"):
    tags = tags if tags is not None else ["unverified"]
    content = f"<rule id='{rid}' level='5'><description>{desc}</description></rule>"
    return RawRule(
        rule_type="wazuh",
        name=name,
        content=content,
        event_id=1,
        event_uuid="uuid-test",
        misp_timestamp=datetime.now(timezone.utc),
        tags=tags,
    )


@pytest.fixture(autouse=True)
def mock_validator_subprocess():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        yield mock_run


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "repository" / "rules"
    return d


def test_tagged_rule_routes_to_quarantine_not_approved(rules_dir):
    rule = make_wazuh_rule()
    stats = process_pending_rules([rule], rules_dir=rules_dir)

    assert stats["quarantined"] == 1
    assert stats["approved"] == 0

    quarantine_file = rules_dir.parent / "generated" / "quarantine" / "wazuh" / "test_rule.xml"
    assert quarantine_file.exists()

    approved_file = rules_dir / "wazuh" / "test_rule.xml"
    assert not approved_file.exists()

    metadata_file = rules_dir.parent / "generated" / "metadata" / "test_rule.json"
    assert metadata_file.exists()
    meta = json.loads(metadata_file.read_text())
    assert meta["deployment_status"] == "quarantined"
    assert "unverified" in meta["tags"]


def test_untagged_rule_does_not_quarantine(rules_dir):
    rule = make_wazuh_rule(name="clean_rule.xml", tags=["tlp:white"])
    stats = process_pending_rules([rule], rules_dir=rules_dir)

    assert stats["quarantined"] == 0
    assert stats["approved"] == 1
    assert (rules_dir / "wazuh" / "clean_rule.xml").exists()
    quarantine_file = rules_dir.parent / "generated" / "quarantine" / "wazuh" / "clean_rule.xml"
    assert not quarantine_file.exists()


def test_list_quarantine_returns_entry_with_metadata(rules_dir):
    rule = make_wazuh_rule()
    process_pending_rules([rule], rules_dir=rules_dir)

    entries = list_quarantined_rules(rules_dir)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["rule_name"] == "test_rule.xml"
    assert entry["rule_type"] == "wazuh"
    assert entry["deployment_status"] == "quarantined"


def test_list_quarantine_empty_when_none(rules_dir):
    entries = list_quarantined_rules(rules_dir)
    assert entries == []


def test_promote_moves_rule_assigns_id_and_rebuilds_xml(rules_dir):
    rule = make_wazuh_rule(desc="unique promote marker")
    process_pending_rules([rule], rules_dir=rules_dir)

    result = promote_quarantined_rule("test_rule.xml", rules_dir)
    assert result["status"] == "ok"
    assert result["rule_type"] == "wazuh"

    quarantine_file = rules_dir.parent / "generated" / "quarantine" / "wazuh" / "test_rule.xml"
    assert not quarantine_file.exists()

    approved_file = rules_dir / "wazuh" / "test_rule.xml"
    assert approved_file.exists()

    local_rules = (rules_dir.parent / "generated" / "local_rules.xml").read_text()
    assert "unique promote marker" in local_rules

    meta_file = rules_dir.parent / "generated" / "metadata" / "test_rule.json"
    meta = json.loads(meta_file.read_text())
    assert meta["deployment_status"] == "pending"
    assert meta["promoted_from_quarantine"] is True


def test_promote_nonexistent_rule_returns_not_found(rules_dir):
    result = promote_quarantined_rule("ghost.xml", rules_dir)
    assert result == {"status": "not_found", "rule_name": "ghost.xml"}


def test_reject_deletes_rule_and_marks_metadata(rules_dir):
    rule = make_wazuh_rule()
    process_pending_rules([rule], rules_dir=rules_dir)

    result = reject_quarantined_rule("test_rule.xml", rules_dir, reason="bad rule, false positives")
    assert result["status"] == "ok"

    quarantine_file = rules_dir.parent / "generated" / "quarantine" / "wazuh" / "test_rule.xml"
    assert not quarantine_file.exists()
    approved_file = rules_dir / "wazuh" / "test_rule.xml"
    assert not approved_file.exists()

    meta_file = rules_dir.parent / "generated" / "metadata" / "test_rule.json"
    meta = json.loads(meta_file.read_text())
    assert meta["deployment_status"] == "rejected"
    assert meta["rejection_reason"] == "bad rule, false positives"


def test_reject_nonexistent_rule_returns_not_found(rules_dir):
    result = reject_quarantined_rule("ghost.xml", rules_dir)
    assert result == {"status": "not_found", "rule_name": "ghost.xml"}


def test_duplicate_content_within_same_batch_only_quarantines_once(rules_dir):
    rule1 = make_wazuh_rule(name="dup1.xml")
    rule2 = make_wazuh_rule(name="dup2.xml")

    stats = process_pending_rules([rule1, rule2], rules_dir=rules_dir)

    assert stats["quarantined"] == 1
    assert stats["duplicated"] == 1


def test_duplicate_content_across_separate_calls(rules_dir):
    """
    KNOWN GAP: existing_hashes only scans rules_dir/{yara,sigma,wazuh},
    never generated/quarantine/. Confirmed via sandbox run -- a rule
    quarantined once gets quarantined AGAIN on the next sync if content
    is unchanged. This test documents actual current behavior.
    """
    rule1 = make_wazuh_rule(name="call1.xml")
    stats1 = process_pending_rules([rule1], rules_dir=rules_dir)
    assert stats1["quarantined"] == 1

    rule2 = make_wazuh_rule(name="call2.xml")
    stats2 = process_pending_rules([rule2], rules_dir=rules_dir)

    assert stats2["quarantined"] == 1
    assert stats2["duplicated"] == 0
