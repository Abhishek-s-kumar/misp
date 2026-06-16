"""
processors package — Orchestrates the pending → approved rule pipeline.

Pipeline steps:
  1. Validate each rule in pending/.
  2. Deduplicate against existing approved/ rules.
  3. Convert Sigma → Wazuh XML.
  4. Move approved rules to approved/<type>/.
  5. Write metadata to metadata/.
"""

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

__all__ = ["process_pending_rules"]


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

    validator = RuleValidator()
    existing_hashes = load_existing_hashes(approved_dir)
    used_ids = get_all_used_ids(rules_dir)

    stats = {
        "total": len(rules),
        "approved": 0,
        "rejected": 0,
        "duplicated": 0,
        "converted": 0,
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
            )
            continue

        # Step 2: Deduplicate
        content_hash = compute_rule_hash(rule.rule_type, rule.content)
        if is_duplicate(rule.rule_type, rule.content, existing_hashes):
            log.info("rule_duplicate_skipped", name=rule.name)
            stats["duplicated"] += 1
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
        )

    # Rebuild all rules into generated/local_rules.xml
    rebuild_local_rules(rules_dir)

    return stats
