import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import structlog

from collector.base import RawRule  # noqa – unused but kept for type ref
from validators.yara_validator import ValidationResult

log = structlog.get_logger()


def write_rule_metadata(
    metadata_dir: Path,
    rule_name: str,
    rule_type: str,
    event_id: int,
    event_uuid: str,
    validation_result: ValidationResult,
    converted: bool = False,
    conversion_target: Optional[str] = None,
    content_hash: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Path:
    """
    Write a JSON metadata document recording the lifecycle of a rule.

    Args:
        metadata_dir: Path to rules/metadata/ directory.
        rule_name: Filename of the rule.
        rule_type: "yara" | "sigma" | "wazuh".
        event_id: Source MISP event ID.
        event_uuid: Source MISP event UUID.
        validation_result: Output from the validator.
        converted: True if the rule was compiled/converted.
        conversion_target: Target format if converted (e.g., "wazuh").
        content_hash: SHA-256 hash of the rule content.

    Returns:
        Path to the written metadata JSON file.
    """
    metadata_dir.mkdir(parents=True, exist_ok=True)

    # Strip extension for metadata filename
    base = rule_name.rsplit(".", 1)[0] if "." in rule_name else rule_name
    meta_file = metadata_dir / f"{base}.json"

    doc = {
        "rule_name": rule_name,
        "rule_type": rule_type,
        "source": "MISP",
        "event_id": event_id,
        "event_uuid": event_uuid,
        "content_hash": content_hash,
        "validation_status": "passed" if validation_result.valid else "failed",
        "validation_errors": validation_result.errors,
        "validation_warnings": validation_result.warnings,
        "conversion_status": "converted" if converted else "none",
        "conversion_target": conversion_target,
        "tags": tags or [],
        "deployment_status": "pending",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    meta_file.write_text(
        json.dumps(doc, indent=2, default=str), encoding="utf-8"
    )
    log.info("metadata_written", file=str(meta_file))
    return meta_file
