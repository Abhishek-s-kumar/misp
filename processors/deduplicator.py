import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Set
import yaml

import structlog

log = structlog.get_logger()


def compute_hash(content: str) -> str:
    """Compute baseline SHA-256 hash of rule content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def canonicalize(val):
    """Recursively canonicalize nested dicts and lists to ensure stable serialization."""
    if isinstance(val, dict):
        return {k: canonicalize(v) for k, v in sorted(val.items())}
    elif isinstance(val, list):
        return [canonicalize(x) for x in val]
    return val


def compute_sigma_hash(content: str) -> str:
    """
    Deduplicate Sigma by title + logsource + detection hash.
    Nested dictionaries and lists are recursively canonicalized before hashing.
    """
    try:
        data = yaml.safe_load(content) or {}
    except Exception:
        data = {}
    title = data.get("title", "")
    logsource = canonicalize(data.get("logsource", {}))
    detection = canonicalize(data.get("detection", {}))

    # Convert canonical dicts/lists to JSON with sorted keys
    ls_str = json.dumps(logsource, sort_keys=True)
    det_str = json.dumps(detection, sort_keys=True)

    canonical_str = f"{title}||{ls_str}||{det_str}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_yara_hash(content: str) -> str:
    """
    Deduplicate YARA by rule name + rule body hash (whitespace & comments stripped).
    """
    name_match = re.search(r'(?:^|\s)rule\s+([a-zA-Z0-9_]+)', content)
    rule_name = name_match.group(1) if name_match else ""

    # Extract body (inside outer curly braces)
    body = ""
    first_brace = content.find("{")
    last_brace = content.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        body = content[first_brace + 1 : last_brace].strip()

    # Strip line and block comments
    body = re.sub(r'//.*', '', body)
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    # Strip all whitespace
    body_normalized = "".join(body.split())

    canonical_str = f"{rule_name}||{body_normalized}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_wazuh_hash(content: str) -> str:
    """
    Deduplicate Wazuh by rule id + content hash (whitespace stripped).

    NOTE: Identical rule content with different rule IDs must be treated as
    distinct rules because rule IDs are unique identifiers in Wazuh used for
    alerting, references (e.g. if_sid), and rule tracking. Therefore, both
    the rule IDs and normalized XML content are factored into the hash.
    """
    rule_ids = []
    try:
        wrapped = f"<root>{content}</root>"
        root = ET.fromstring(wrapped)
        for rule in root.findall(".//rule"):
            rid = rule.get("id")
            if rid:
                rule_ids.append(rid)
    except Exception:
        pass

    # Normalize content by stripping all whitespace and comments
    # XML comments: <!-- comment -->
    normalized_content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
    normalized_content = "".join(normalized_content.split())

    ids_str = ",".join(sorted(rule_ids))
    canonical_str = f"{ids_str}||{normalized_content}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def compute_rule_hash(rule_type: str, content: str) -> str:
    """Compute type-specific hash for deduplication."""
    if rule_type == "sigma":
        return compute_sigma_hash(content)
    elif rule_type == "yara":
        return compute_yara_hash(content)
    elif rule_type == "wazuh":
        return compute_wazuh_hash(content)
    return compute_hash(content)


def load_existing_hashes(rules_dir: Path) -> Set[str]:
    """
    Scan all files under rules/ subdirectories and compute their type-specific
    content hashes. Returns a set of known SHA-256 hashes.
    """
    hashes: Set[str] = set()
    if not rules_dir.exists():
        return hashes

    for rule_file in rules_dir.rglob("*"):
        if rule_file.is_file() and not rule_file.name.startswith("."):
            try:
                ext = rule_file.suffix.lower()
                parent_name = rule_file.parent.name.lower()

                rule_type = None
                if ext in (".yar", ".yara") or parent_name == "yara":
                    rule_type = "yara"
                elif ext in (".yml", ".yaml") or parent_name == "sigma":
                    rule_type = "sigma"
                elif ext == ".xml" or parent_name == "wazuh":
                    rule_type = "wazuh"

                if not rule_type:
                    continue

                content = rule_file.read_text(encoding="utf-8")
                rule_hash = compute_rule_hash(rule_type, content)
                hashes.add(rule_hash)
            except Exception as e:
                log.warning(
                    "hash_read_failed", file=str(rule_file), error=str(e)
                )
    return hashes


def is_duplicate(*args, **kwargs) -> bool:
    """
    Return True if the type-specific rule hash already exists.
    Supports legacy callers: is_duplicate(content, existing_hashes) -> baseline SHA256 check.
    Supports new callers: is_duplicate(rule_type, content, existing_hashes) -> type-specific check.
    """
    if len(args) == 2:
        content, existing_hashes = args
        return compute_hash(content) in existing_hashes
    elif len(args) == 3:
        rule_type, content, existing_hashes = args
    else:
        rule_type = kwargs.get("rule_type")
        content = kwargs.get("content", "")
        existing_hashes = kwargs.get("existing_hashes", set())
        if not rule_type:
            return compute_hash(content) in existing_hashes

    return compute_rule_hash(rule_type, content) in existing_hashes
