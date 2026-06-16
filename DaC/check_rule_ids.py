"""
check_rule_ids.py — Rule ID conflict checker for the DaC repository CI.

Checks all changed rule files (Wazuh XML and Sigma YAML) in a PR against
the existing IDs on the main branch to detect conflicts.

Behaviours:
  - XML files: extract <rule id="..."> attributes.
  - Sigma YAML files: extract custom.wazuh_rule_id fields.
  - Skips YARA files (.yar/.yara) — YARA rules have no numeric IDs.
  - Detects internal duplicates within a single file.
  - Detects cross-file conflicts with IDs already present on main.
"""

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import sys
from collections import defaultdict, Counter

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def run_git_command(args):
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return result.stdout


def get_changed_rule_files():
    """Return (status, Path) tuples for all changed rule files in this PR."""
    try:
        output = run_git_command(["git", "diff", "--name-status", "origin/main...HEAD"])
        changed_files = []
        for line in output.strip().splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2:
                continue
            status, file_path = parts
            p = Path(file_path)
            # Include Wazuh XML and Sigma YAML; skip YARA and generated artefacts
            if p.suffix.lower() in (".xml", ".yml", ".yaml"):
                # Only check rule source directories; skip generated/ and metadata/
                if p.parts and p.parts[0] in ("rules", "generated") and "conversion_cache" not in p.parts:
                    changed_files.append((status, p))
        return changed_files
    except subprocess.CalledProcessError as e:
        print("❌ Failed to get changed files:", e)
        sys.exit(1)


def extract_ids_from_xml(content: str) -> list:
    """Extract integer rule IDs from a Wazuh XML fragment."""
    ids = []
    try:
        wrapped = f"<root>{content}</root>"
        root = ET.fromstring(wrapped)
        for rule in root.findall(".//rule"):
            rule_id = rule.get("id")
            if rule_id and rule_id.isdigit():
                ids.append(int(rule_id))
    except ET.ParseError as e:
        print(f"⚠️  XML Parse Error: {e}")
    return ids


def extract_ids_from_sigma(content: str) -> list:
    """Extract wazuh_rule_id from Sigma YAML custom block."""
    if not _YAML_AVAILABLE:
        return []
    try:
        data = yaml.safe_load(content) or {}
        custom = data.get("custom", {})
        if isinstance(custom, dict) and "wazuh_rule_id" in custom:
            rid = custom["wazuh_rule_id"]
            if isinstance(rid, int):
                return [rid]
    except Exception:
        pass
    return []


def extract_ids_from_file(path: Path, content: str) -> list:
    """Dispatch to the correct extractor based on file extension."""
    ext = path.suffix.lower()
    if ext == ".xml":
        return extract_ids_from_xml(content)
    elif ext in (".yml", ".yaml"):
        return extract_ids_from_sigma(content)
    return []  # YARA and others — no numeric IDs


def get_rule_ids_per_file_in_main() -> dict:
    """Build a mapping of rule_id -> set(file_paths) from the main branch."""
    run_git_command(["git", "fetch", "origin", "main"])
    files_output = run_git_command(["git", "ls-tree", "-r", "origin/main", "--name-only"])

    rule_id_to_files = defaultdict(set)
    for file in files_output.splitlines():
        p = Path(file)
        if p.suffix.lower() not in (".xml", ".yml", ".yaml"):
            continue
        if not (p.parts and p.parts[0] in ("rules", "generated")):
            continue
        try:
            content = run_git_command(["git", "show", f"origin/main:{file}"])
            rule_ids = extract_ids_from_file(p, content)
            for rule_id in rule_ids:
                rule_id_to_files[rule_id].add(file)
        except subprocess.CalledProcessError:
            continue
    return rule_id_to_files


def get_ids_from_main_version(file_path: Path) -> list:
    """Get the rule IDs from the main-branch version of a file (for M status)."""
    try:
        content = run_git_command(["git", "show", f"origin/main:{file_path.as_posix()}"])
        return extract_ids_from_file(file_path, content)
    except subprocess.CalledProcessError:
        return []


def detect_duplicates(rule_ids: list) -> list:
    counter = Counter(rule_ids)
    return [rule_id for rule_id, count in counter.items() if count > 1]


def print_conflicts(conflicting_ids, rule_id_to_files):
    print("❌ Conflicts detected:")
    for rule_id in sorted(conflicting_ids):
        files = rule_id_to_files.get(rule_id, [])
        print(f"  - Rule ID {rule_id} found in:")
        for f in sorted(files):
            print(f"    • {f}")


def main():
    changed_files = get_changed_rule_files()
    if not changed_files:
        print("✅ No rule files changed in this PR.")
        return

    rule_id_to_files_main = get_rule_ids_per_file_in_main()

    print(f"🔍 Checking rule ID conflicts for: {[str(f) for _, f in changed_files]}")

    has_conflict = False

    for status, path in changed_files:
        print(f"\n🔎 Checking: {path}")

        # Skip YARA — no numeric IDs to conflict
        if path.suffix.lower() in (".yar", ".yara"):
            print(f"ℹ️  YARA file {path.name} — no numeric IDs, skipping.")
            continue

        try:
            dev_content = path.read_text(encoding="utf-8")
            dev_ids = extract_ids_from_file(path, dev_content)
        except Exception as e:
            print(f"⚠️  Could not read {path}: {e}")
            continue

        if not dev_ids:
            print(f"ℹ️  {path.name} — no rule IDs found.")
            continue

        # Check for internal duplicates
        duplicates = detect_duplicates(dev_ids)
        if duplicates:
            print(f"❌ Duplicate rule IDs in {path.name}: {sorted(duplicates)}")
            has_conflict = True
            continue

        if status == "A":
            # New file — check all IDs against main
            conflicting_ids = set(dev_ids) & set(rule_id_to_files_main.keys())
            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_main)
                has_conflict = True
            else:
                print(f"✅ New file {path.name} — no conflicts.")

        elif status == "M":
            # Modified file — only check genuinely new IDs
            main_ids = get_ids_from_main_version(path)
            if set(dev_ids) == set(main_ids):
                print(f"ℹ️  {path.name} modified but rule IDs unchanged.")
                continue

            new_ids = set(dev_ids) - set(main_ids)
            conflicting_ids = new_ids & set(rule_id_to_files_main.keys())

            if conflicting_ids:
                print_conflicts(conflicting_ids, rule_id_to_files_main)
                has_conflict = True
            else:
                print(f"✅ Modified file {path.name} — no conflicting IDs.")

    if has_conflict:
        sys.exit(1)

    print("\n✅ All rule file changes passed conflict checks.")


if __name__ == "__main__":
    main()
