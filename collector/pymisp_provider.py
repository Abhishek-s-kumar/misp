import base64
import os
from datetime import datetime
from typing import List, Optional

import structlog
from pymisp import PyMISP
from tenacity import retry, stop_after_attempt, wait_exponential

from collector.base import MISPRuleProvider, RawRule

log = structlog.get_logger()

# File extensions that map to rule types
EXTENSION_MAP = {
    ".yar": "yara",
    ".yara": "yara",
    ".yml": "sigma",
    ".yaml": "sigma",
    ".xml": "wazuh",
}

# MISP attribute types we extract rules from
ATTRIBUTE_TYPES = {"yara", "sigma"}

# MISP object types we extract rules from
OBJECT_TYPES = {"yara", "sigma"}


class PyMISPRuleProvider(MISPRuleProvider):
    """
    Retrieves detection rules from a live MISP instance via PyMISP.

    Supported extraction sources:
      1. MISP Attributes of type 'yara' or 'sigma'.
      2. MISP Objects of type 'yara' or 'sigma'.
      3. File attachments with extensions: .yar, .yara, .yml, .yaml, .xml.
    """

    def __init__(self):
        self.url = os.environ["MISP_URL"]
        self.api_key = os.environ["MISP_API_KEY"]
        self.verify_ssl = os.getenv("MISP_VERIFY_SSL", "false").lower() in (
            "true",
            "1",
        )
        self.client = PyMISP(self.url, self.api_key, ssl=self.verify_ssl)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    def fetch_rules(
        self,
        rule_types: List[str],
        tags: List[str],
        since: Optional[datetime] = None,
    ) -> List[RawRule]:
        search_kwargs: dict = {"pythonify": True}
        if since:
            search_kwargs["timestamp"] = int(since.timestamp())
        if tags:
            search_kwargs["tags"] = tags

        events = self.client.search("events", **search_kwargs)
        log.info("pymisp_events_fetched", count=len(events))

        raw_rules: List[RawRule] = []

        for event in events:
            event_id = int(event.id)
            event_uuid = str(event.uuid)
            event_ts = datetime.utcfromtimestamp(int(event.timestamp.timestamp()))

            # --- Source 1: Attributes ---
            for attr in event.get("Attribute", []):
                attr_type = attr.get("type", "")
                if attr_type not in ATTRIBUTE_TYPES:
                    continue
                if attr_type not in rule_types:
                    continue

                rule_name = attr.get("comment", "") or f"{attr_type}_{attr['id']}"
                content = attr.get("value", "")

                # If the value is base64-encoded data, decode it
                if attr.get("data"):
                    try:
                        content = base64.b64decode(attr["data"]).decode("utf-8")
                    except Exception:
                        content = attr.get("value", "")

                raw_rules.append(
                    RawRule(
                        rule_type=attr_type,
                        name=self._sanitize_filename(rule_name, attr_type),
                        content=content,
                        event_id=event_id,
                        event_uuid=event_uuid,
                        misp_timestamp=event_ts,
                        tags=[t.get("name", "") for t in attr.get("Tag", [])],
                    )
                )

            # --- Source 2: Objects ---
            for obj in event.get("Object", []):
                obj_name = obj.get("name", "")
                if obj_name not in OBJECT_TYPES:
                    continue
                if obj_name not in rule_types:
                    continue

                rule_content = ""
                rule_filename = ""
                for obj_attr in obj.get("Attribute", []):
                    rel = obj_attr.get("object_relation", "")
                    if rel in ("yara", "sigma", "rule", "content"):
                        rule_content = obj_attr.get("value", "")
                        if obj_attr.get("data"):
                            try:
                                rule_content = base64.b64decode(
                                    obj_attr["data"]
                                ).decode("utf-8")
                            except Exception:
                                pass
                    if rel in ("name", "rule-name"):
                        rule_filename = obj_attr.get("value", "")

                if not rule_content:
                    continue

                if not rule_filename:
                    rule_filename = f"{obj_name}_obj_{obj.get('id', 'unknown')}"

                raw_rules.append(
                    RawRule(
                        rule_type=obj_name,
                        name=self._sanitize_filename(rule_filename, obj_name),
                        content=rule_content,
                        event_id=event_id,
                        event_uuid=event_uuid,
                        misp_timestamp=event_ts,
                        tags=[t.get("name", "") for t in obj.get("Tag", [])],
                    )
                )

            # --- Source 3: Attachments ---
            for attr in event.get("Attribute", []):
                if attr.get("type") != "attachment":
                    continue

                filename = attr.get("value", "")
                ext = self._get_extension(filename)
                if ext not in EXTENSION_MAP:
                    continue

                inferred_type = EXTENSION_MAP[ext]
                if inferred_type not in rule_types:
                    continue

                # Download the attachment content
                try:
                    attachment_data = self.client.get_attachment(attr["id"])
                    if isinstance(attachment_data, bytes):
                        content = attachment_data.decode("utf-8")
                    else:
                        content = str(attachment_data)
                except Exception as e:
                    log.warning(
                        "attachment_download_failed",
                        attr_id=attr["id"],
                        error=str(e),
                    )
                    continue

                raw_rules.append(
                    RawRule(
                        rule_type=inferred_type,
                        name=filename,
                        content=content,
                        event_id=event_id,
                        event_uuid=event_uuid,
                        misp_timestamp=event_ts,
                        tags=[t.get("name", "") for t in attr.get("Tag", [])],
                    )
                )

        log.info("pymisp_rules_extracted", count=len(raw_rules))
        return raw_rules

    @staticmethod
    def _sanitize_filename(name: str, rule_type: str) -> str:
        """Ensure the filename has a proper extension for its type."""
        ext_map = {"yara": ".yar", "sigma": ".yml", "wazuh": ".xml"}
        expected_ext = ext_map.get(rule_type, "")
        if expected_ext and not name.endswith(expected_ext):
            name = name + expected_ext
        # Replace unsafe characters
        safe = "".join(c if c.isalnum() or c in (".", "_", "-") else "_" for c in name)
        return safe

    @staticmethod
    def _get_extension(filename: str) -> str:
        """Return the lowercase file extension including the dot."""
        dot_idx = filename.rfind(".")
        if dot_idx == -1:
            return ""
        return filename[dot_idx:].lower()
