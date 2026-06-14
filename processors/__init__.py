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
from processors.deduplicator import compute_hash, is_duplicate, load_existing_hashes
from processors.metadata_writer import write_rule_metadata
from processors.sigma_converter import convert_sigma_to_wazuh
from validators import RuleValidator, ValidationResult

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
    3. Convert Sigma rules to Wazuh XML.
    4. Write approved rules and metadata.

    Args:
        rules: List of RawRule objects from the collector.
        rules_dir: Path to repository/rules/ (contains pending/, approved/, metadata/).

    Returns:
        Summary dict with counts for approved, rejected, duplicated, converted rules.
    """
    pending_dir = rules_dir / "pending"
    approved_dir = rules_dir / "approved"
    metadata_dir = rules_dir / "metadata"

    # Ensure directories exist
    for d in [
        pending_dir,
        approved_dir / "yara",
        approved_dir / "sigma",
        approved_dir / "wazuh",
        metadata_dir,
    ]:
        d.mkdir(parents=True, exist_ok=True)

    validator = RuleValidator()
    existing_hashes = load_existing_hashes(approved_dir)

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
        content_hash = compute_hash(rule.content)
        if is_duplicate(rule.content, existing_hashes):
            log.info("rule_duplicate_skipped", name=rule.name)
            stats["duplicated"] += 1
            continue

        # Step 3: Sigma → Wazuh conversion
        converted = False
        conversion_target = None
        if rule.rule_type == "sigma":
            wazuh_xml = convert_sigma_to_wazuh(rule.content, rule.name)
            if wazuh_xml:
                converted_name = rule.name.rsplit(".", 1)[0] + ".xml"
                dest = approved_dir / "wazuh" / converted_name
                dest.write_text(wazuh_xml, encoding="utf-8")
                existing_hashes.add(compute_hash(wazuh_xml))
                converted = True
                conversion_target = "wazuh"
                stats["converted"] += 1
                log.info("sigma_converted_to_wazuh", name=converted_name)

            # Also store the original Sigma YAML for audit
            sigma_dest = approved_dir / "sigma" / rule.name
            sigma_dest.write_text(rule.content, encoding="utf-8")

        elif rule.rule_type == "yara":
            dest = approved_dir / "yara" / rule.name
            dest.write_text(rule.content, encoding="utf-8")

        elif rule.rule_type == "wazuh":
            dest = approved_dir / "wazuh" / rule.name
            dest.write_text(rule.content, encoding="utf-8")

        # Track hash to prevent future duplicates within same batch
        existing_hashes.add(content_hash)

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

        stats["approved"] += 1
        log.info("rule_approved", name=rule.name, type=rule.rule_type)

    return stats
