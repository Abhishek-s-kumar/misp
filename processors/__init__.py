"""
processors package — Orchestrates the pending → approved rule pipeline.

Pipeline steps:
  1. Validate each rule in pending/.
  2. Deduplicate against existing approved/ rules.
  3. Convert Sigma → Wazuh XML.
  4. Move approved rules to approved/<type>/.
  5. Write metadata to metadata/.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any

import structlog

from collector.base import RawRule
from processors.deduplicator import compute_hash, compute_rule_hash, is_duplicate, load_existing_hashes
from processors.metadata_writer import write_rule_metadata
from validators import RuleValidator, ValidationResult
from processors.xml_merger import (
    get_all_used_ids,
    get_or_assign_sigma_id,
    get_or_assign_wazuh_ids,
    rebuild_local_rules,
)

log = structlog.get_logger()

__all__ = ["process_pending_rules", "promote_quarantined_rule", "list_quarantined_rules", "reject_quarantined_rule"]


def process_pending_rules(
    rules: List[RawRule],
    rules_dir: Path,
) -> Dict[str, Any]:
    """
    Run the full processing pipeline on a list of raw rules.

    1. Validate each rule.
    2. Skip duplicates.
    3. Write approved rules to approved/ (source) folders.
    4. Allocate/persist IDs for Sigma & Wazuh source rules.
    5. Write metadata.
    6. Rebuild generated/local_rules.xml.

    Args:
        rules: List of RawRule objects from the collector.
        rules_dir: Path to repository/rules/ (contains sigma/, yara/, wazuh/).

    Returns:
        Summary dict with counts for approved, rejected, duplicated, converted rules.
    """
    pending_dir = rules_dir.parent / "generated" / "pending"
    approved_dir = rules_dir
    metadata_dir = rules_dir.parent / "generated" / "metadata"

    # Ensure directories exist
    pending_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (approved_dir / "yara").mkdir(parents=True, exist_ok=True)
    (approved_dir / "sigma").mkdir(parents=True, exist_ok=True)
    (approved_dir / "wazuh").mkdir(parents=True, exist_ok=True)
    (rules_dir.parent / "generated" / "conversion_cache").mkdir(parents=True, exist_ok=True)

    quarantine_dir = rules_dir.parent / "generated" / "quarantine"
    (quarantine_dir / "yara").mkdir(parents=True, exist_ok=True)
    (quarantine_dir / "sigma").mkdir(parents=True, exist_ok=True)
    (quarantine_dir / "wazuh").mkdir(parents=True, exist_ok=True)

    quarantine_tags = {t.strip() for t in os.getenv("QUARANTINE_TAGS", "unverified").split(",") if t.strip()}

    validator = RuleValidator()
    existing_hashes = load_existing_hashes(approved_dir)
    used_ids = get_all_used_ids(rules_dir)

    stats = {
        "total": len(rules),
        "approved": 0,
        "rejected": 0,
        "duplicated": 0,
        "converted": 0,
        "quarantined": 0,
        "errors": [],
    }

    for rule in rules:
        # Step 0: Write to pending/ for audit trail
        pending_file = pending_dir / rule.name
        pending_file.write_text(rule.content, encoding="utf-8")

        # Step 1: Validate
        result = validator.validate(rule)
        if not result.valid:
            log.warning(
                "rule_rejected",
                name=rule.name,
                errors=result.errors,
            )
            stats["rejected"] += 1
            stats["errors"].append(
                {"rule": rule.name, "errors": result.errors}
            )
            # Write metadata even for failures
            write_rule_metadata(
                metadata_dir=metadata_dir,
                rule_name=rule.name,
                rule_type=rule.rule_type,
                event_id=rule.event_id,
                event_uuid=rule.event_uuid,
                validation_result=result,
                content_hash=compute_hash(rule.content),
                tags=rule.tags,
            )
            continue

        # Step 2: Deduplicate
        content_hash = compute_rule_hash(rule.rule_type, rule.content)
        if is_duplicate(rule.rule_type, rule.content, existing_hashes):
            log.info("rule_duplicate_skipped", name=rule.name)
            stats["duplicated"] += 1
            continue

        # Step 2b: Quarantine gate — tagged content sits here until manually promoted,
        # never reaches approved_dir/rules_dir, so rebuild_local_rules() never sees it.
        if quarantine_tags & set(rule.tags or []):
            log.info("rule_quarantined", name=rule.name, tags=rule.tags)
            dest = quarantine_dir / rule.rule_type / rule.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(rule.content, encoding="utf-8")
            write_rule_metadata(
                metadata_dir=metadata_dir,
                rule_name=rule.name,
                rule_type=rule.rule_type,
                event_id=rule.event_id,
                event_uuid=rule.event_uuid,
                validation_result=result,
                content_hash=content_hash,
                tags=rule.tags,
                deployment_status="quarantined",
            )
            stats["quarantined"] += 1
            existing_hashes.add(content_hash)
            continue

        # Step 3: Write to approved source directory & Assign IDs
        converted = False
        conversion_target = None

        if rule.rule_type == "sigma":
            dest = approved_dir / "sigma" / rule.name
            dest.write_text(rule.content, encoding="utf-8")
            # Persist and get ID in the source file
            get_or_assign_sigma_id(dest, used_ids)
            converted = True
            conversion_target = "wazuh"
            stats["converted"] += 1
            log.info("sigma_approved_and_id_assigned", name=rule.name)

        elif rule.rule_type == "yara":
            dest = approved_dir / "yara" / rule.name
            dest.write_text(rule.content, encoding="utf-8")

        elif rule.rule_type == "wazuh":
            dest = approved_dir / "wazuh" / rule.name
            dest.write_text(rule.content, encoding="utf-8")
            # Assign rules IDs in the source file
            get_or_assign_wazuh_ids(dest, used_ids)

        # Track hash to prevent future duplicates within same batch
        existing_hashes.add(content_hash)
        stats["approved"] += 1

        # Step 4: Write metadata
        write_rule_metadata(
            metadata_dir=metadata_dir,
            rule_name=rule.name,
            rule_type=rule.rule_type,
            event_id=rule.event_id,
            event_uuid=rule.event_uuid,
            validation_result=result,
            converted=converted,
            conversion_target=conversion_target,
            content_hash=content_hash,
            tags=rule.tags,
        )

    # Rebuild all rules into generated/local_rules.xml
    rebuild_local_rules(rules_dir)

    return stats


def list_quarantined_rules(rules_dir: Path) -> list:
    """
    Return metadata for every rule currently sitting in quarantine, across all types.
    """
    quarantine_dir = rules_dir.parent / "generated" / "quarantine"
    metadata_dir = rules_dir.parent / "generated" / "metadata"
    results = []
    for rule_type in ("sigma", "yara", "wazuh"):
        type_dir = quarantine_dir / rule_type
        if not type_dir.exists():
            continue
        for rule_file in type_dir.iterdir():
            if not rule_file.is_file():
                continue
            base = rule_file.name.rsplit(".", 1)[0] if "." in rule_file.name else rule_file.name
            meta_file = metadata_dir / f"{base}.json"
            entry = {"rule_name": rule_file.name, "rule_type": rule_type}
            if meta_file.exists():
                try:
                    entry.update(json.loads(meta_file.read_text(encoding="utf-8")))
                except Exception as e:
                    log.warning("quarantine_metadata_read_failed", file=str(meta_file), error=str(e))
            results.append(entry)
    return results


def promote_quarantined_rule(rule_name: str, rules_dir: Path) -> Dict[str, Any]:
    """
    Move a manually-reviewed rule out of quarantine into the real approved directory,
    assign IDs if needed, update its metadata, and rebuild generated/local_rules.xml
    so the promotion actually takes effect.

    Args:
        rule_name: filename of the rule (as it appears under generated/quarantine/<type>/).
        rules_dir: path to repository/rules/ (contains sigma/, yara/, wazuh/).

    Returns:
        dict with "status": "ok" | "not_found" | "error", and details.
    """
    quarantine_dir = rules_dir.parent / "generated" / "quarantine"
    metadata_dir = rules_dir.parent / "generated" / "metadata"

    src = None
    rule_type = None
    for candidate_type in ("sigma", "yara", "wazuh"):
        candidate = quarantine_dir / candidate_type / rule_name
        if candidate.exists():
            src = candidate
            rule_type = candidate_type
            break

    if src is None:
        return {"status": "not_found", "rule_name": rule_name}

    used_ids = get_all_used_ids(rules_dir)
    dest = rules_dir / rule_type / rule_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    if rule_type == "sigma":
        get_or_assign_sigma_id(dest, used_ids)
    elif rule_type == "wazuh":
        get_or_assign_wazuh_ids(dest, used_ids)

    src.unlink()

    base = rule_name.rsplit(".", 1)[0] if "." in rule_name else rule_name
    meta_file = metadata_dir / f"{base}.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            meta["deployment_status"] = "pending"
            meta["promoted_from_quarantine"] = True
            meta_file.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        except Exception as e:
            log.warning("promote_metadata_update_failed", rule_name=rule_name, error=str(e))

    rebuild_local_rules(rules_dir)
    log.info("rule_promoted_from_quarantine", rule_name=rule_name, rule_type=rule_type)

    return {"status": "ok", "rule_name": rule_name, "rule_type": rule_type}

def reject_quarantined_rule(rule_name: str, rules_dir: Path, reason: str = "") -> Dict[str, Any]:
    """
    Permanently discard a quarantined rule: delete the quarantined file,
    mark its metadata as rejected (audit trail kept), never touches
    approved_dir/rules_dir.
    """
    quarantine_dir = rules_dir.parent / "generated" / "quarantine"
    metadata_dir = rules_dir.parent / "generated" / "metadata"

    src = None
    for candidate_type in ("sigma", "yara", "wazuh"):
        candidate = quarantine_dir / candidate_type / rule_name
        if candidate.exists():
            src = candidate
            break

    if src is None:
        return {"status": "not_found", "rule_name": rule_name}

    src.unlink()

    base = rule_name.rsplit(".", 1)[0] if "." in rule_name else rule_name
    meta_file = metadata_dir / f"{base}.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            meta["deployment_status"] = "rejected"
            meta["rejection_reason"] = reason
            meta_file.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        except Exception as e:
            log.warning("reject_metadata_update_failed", rule_name=rule_name, error=str(e))

    log.info("rule_rejected_from_quarantine", rule_name=rule_name, reason=reason)
    return {"status": "ok", "rule_name": rule_name}

