import hashlib
from pathlib import Path
from typing import Set

import structlog

log = structlog.get_logger()


def compute_hash(content: str) -> str:
    """Compute SHA-256 hash of rule content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def load_existing_hashes(approved_dir: Path) -> Set[str]:
    """
    Scan all files under approved/ subdirectories and compute their
    content hashes. Returns a set of known SHA-256 hashes.
    """
    hashes: Set[str] = set()
    if not approved_dir.exists():
        return hashes

    for rule_file in approved_dir.rglob("*"):
        if rule_file.is_file() and not rule_file.name.startswith("."):
            try:
                content = rule_file.read_text(encoding="utf-8")
                hashes.add(compute_hash(content))
            except Exception as e:
                log.warning(
                    "hash_read_failed", file=str(rule_file), error=str(e)
                )
    return hashes


def is_duplicate(content: str, existing_hashes: Set[str]) -> bool:
    """Return True if the content hash already exists in approved/."""
    return compute_hash(content) in existing_hashes
