import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Set, List
import yaml

import structlog
from processors.sigma_converter import convert_sigma_to_wazuh

log = structlog.get_logger()


def next_available_id(used_ids: Set[int]) -> int:
    """Find the next available rule ID in the MISP range 200000-299999."""
    for rid in range(200000, 300000):
        if rid not in used_ids:
            used_ids.add(rid)
            return rid
    raise ValueError("Rule ID range 200000-299999 is exhausted.")


def get_all_used_ids(rules_dir: Path) -> Set[int]:
    """Scan wazuh rules, sigma rules, and the generated local_rules.xml to collect all allocated IDs."""
    used = set()
    
    # 1. Scan approved wazuh XMLs
    wazuh_dir = rules_dir / "wazuh"
    if wazuh_dir.exists():
        for f in wazuh_dir.glob("*.xml"):
            try:
                content = f.read_text(encoding="utf-8")
                wrapped = f"<root>{content}</root>"
                root = ET.fromstring(wrapped)
                for rule in root.findall(".//rule"):
                    rid = rule.get("id")
                    if rid and rid.isdigit():
                        used.add(int(rid))
            except Exception:
                pass

    # 2. Scan approved sigma YAMLs
    sigma_dir = rules_dir / "sigma"
    if sigma_dir.exists():
        for f in list(sigma_dir.glob("*.yml")) + list(sigma_dir.glob("*.yaml")):
            try:
                content = f.read_text(encoding="utf-8")
                data = yaml.safe_load(content) or {}
                custom = data.get("custom", {})
                if isinstance(custom, dict) and "wazuh_rule_id" in custom:
                    rid = custom["wazuh_rule_id"]
                    if isinstance(rid, int):
                        used.add(rid)
            except Exception:
                pass

    # 3. Scan generated/local_rules.xml
    gen_file = rules_dir.parent / "generated" / "local_rules.xml"
    if gen_file.exists():
        try:
            content = gen_file.read_text(encoding="utf-8")
            root = ET.fromstring(content)
            for rule in root.findall(".//rule"):
                rid = rule.get("id")
                if rid and rid.isdigit():
                    used.add(int(rid))
        except Exception:
            pass

    return used


def get_or_assign_sigma_id(file_path: Path, used_ids: Set[int]) -> int:
    """Extract the wazuh_rule_id from the Sigma rule, or allocate and persist a new one."""
    try:
        content = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
    except Exception:
        data = {}

    custom = data.get("custom", {})
    if isinstance(custom, dict) and "wazuh_rule_id" in custom:
        rid = custom["wazuh_rule_id"]
        if isinstance(rid, int):
            used_ids.add(rid)
            return rid

    # Allocate new
    new_id = next_available_id(used_ids)
    if "custom" not in data or not isinstance(data["custom"], dict):
        data["custom"] = {}
    data["custom"]["wazuh_rule_id"] = new_id

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False)
    except Exception as e:
        log.error("failed_to_persist_sigma_id", file=str(file_path), error=str(e))

    return new_id


def get_or_assign_wazuh_ids(file_path: Path, used_ids: Set[int]) -> bool:
    """Scan and assign/fix rule IDs in a Wazuh XML rule file, keeping them in the 200000-299999 range."""
    try:
        content = file_path.read_text(encoding="utf-8")
        # Ensure it has a root element to parse properly
        if not content.strip().startswith("<group") and not content.strip().startswith("<rule"):
            return False
        wrapped = f"<root>{content}</root>"
        root = ET.fromstring(wrapped)
    except Exception:
        return False

    changed = False
    rules = []
    if root.tag == "rule":
        rules.append(root)
    rules.extend(root.findall(".//rule"))

    for rule in rules:
        rid = rule.get("id")
        if not rid or not rid.isdigit() or int(rid) < 100000 or int(rid) > 199999 or int(rid) in used_ids:
            new_id = next_available_id(used_ids)
            rule.set("id", str(new_id))
            changed = True
        else:
            used_ids.add(int(rid))

    if changed:
        try:
            # If the original content had a root <group>, serialize its children,
            # otherwise serialize the modified rules.
            # Simple serialization: strip the <root> wrapper
            content_new = "".join(ET.tostring(child, encoding="utf-8").decode("utf-8") for child in root)
            file_path.write_text(content_new, encoding="utf-8")
        except Exception as e:
            log.error("failed_to_write_assigned_wazuh_ids", file=str(file_path), error=str(e))
    return changed


def override_xml_rule_ids(xml_content: str, target_id: int) -> str:
    """Parse output XML and override the rule ID attribute(s) with the target ID."""
    try:
        wrapped = f"<root>{xml_content}</root>"
        root = ET.fromstring(wrapped)
        rules = root.findall(".//rule")
        for i, rule in enumerate(rules):
            rule.set("id", str(target_id + i))
        return "".join(ET.tostring(child, encoding="utf-8").decode("utf-8") for child in root)
    except Exception as e:
        log.warning("xml_override_failed_falling_back_to_regex", error=str(e))
        return re.sub(r'id="\d+"', f'id="{target_id}"', xml_content)


def merge_wazuh_xml_files(xml_contents: List[str]) -> str:
    """Merge rule tags from all XML contents under a single group element, verifying IDs."""
    group_el = ET.Element("group", name="misp,")
    seen_ids = set()

    for content in xml_contents:
        if not content.strip():
            continue
        try:
            # Wrap to handle multiple root elements cleanly
            wrapped = f"<root>{content}</root>"
            root = ET.fromstring(wrapped)
            for rule in root.findall(".//rule"):
                rid = rule.get("id")
                if rid:
                    if rid in seen_ids:
                        raise ValueError(f"Duplicate rule ID detected during XML compilation: {rid}")
                    seen_ids.add(rid)
                group_el.append(rule)
        except ET.ParseError as e:
            raise ValueError(f"Malformed XML detected: {e}")

    try:
        ET.indent(group_el, space="  ", level=0)
    except AttributeError:
        pass
    return ET.tostring(group_el, encoding="utf-8").decode("utf-8")


def rebuild_local_rules(rules_dir: Path):
    """Compile all rules (wazuh and converted sigma) in rules_dir into a single local_rules.xml."""
    generated_dir = rules_dir.parent / "generated"
    cache_dir = generated_dir / "conversion_cache"
    generated_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    xml_parts = []

    # 1. Parse approved wazuh XMLs
    wazuh_dir = rules_dir / "wazuh"
    if wazuh_dir.exists():
        for f in sorted(wazuh_dir.glob("*.xml")):
            try:
                content = f.read_text(encoding="utf-8")
                if content.strip():
                    xml_parts.append(content)
            except Exception as e:
                log.error("failed_to_read_wazuh_rule_for_merge", file=str(f), error=str(e))

    # 2. Parse approved sigma YAMLs
    sigma_dir = rules_dir / "sigma"
    if sigma_dir.exists():
        for f in sorted(list(sigma_dir.glob("*.yml")) + list(sigma_dir.glob("*.yaml"))):
            try:
                content = f.read_text(encoding="utf-8")
                data = yaml.safe_load(content) or {}
                custom = data.get("custom", {})
                wazuh_rule_id = custom.get("wazuh_rule_id") if isinstance(custom, dict) else None
                if not wazuh_rule_id:
                    continue

                wazuh_xml = convert_sigma_to_wazuh(content, f.name)
                if not wazuh_xml:
                    continue

                # Save intermediate to conversion cache
                cache_file = cache_dir / f"{f.stem}.xml"
                cache_file.write_text(wazuh_xml, encoding="utf-8")

                # Override and append
                overridden = override_xml_rule_ids(wazuh_xml, wazuh_rule_id)
                xml_parts.append(overridden)
            except Exception as e:
                log.error("failed_to_convert_sigma_rule_for_merge", file=str(f), error=str(e))

    # 3. Merge and compile
    merged_xml = merge_wazuh_xml_files(xml_parts)

    # 4. Write generated/local_rules.xml
    output_file = generated_dir / "local_rules.xml"
    output_file.write_text(merged_xml, encoding="utf-8")
    log.info("rebuild_local_rules_success", output_file=str(output_file))
