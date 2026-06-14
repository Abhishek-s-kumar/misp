import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from collector.base import MISPRuleProvider, RawRule


class MockMISPRuleProvider(MISPRuleProvider):
    """
    Returns rules from a local JSON fixture file.
    For local development and testing without a real MISP instance.
    """

    def __init__(self, fixture_path: Path = Path("fixtures/mock_rules.json")):
        self.fixture_path = fixture_path

    def fetch_rules(
        self,
        rule_types: List[str],
        tags: List[str],
        since: Optional[datetime] = None,
    ) -> List[RawRule]:
        if not self.fixture_path.exists():
            root_dir = Path(__file__).resolve().parent.parent
            resolved_path = root_dir / self.fixture_path
            if resolved_path.exists():
                self.fixture_path = resolved_path
            else:
                raise FileNotFoundError(
                    f"Fixture file not found: {self.fixture_path}"
                )

        with open(self.fixture_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_rules: List[RawRule] = []
        for entry in data:
            ts = datetime.fromisoformat(entry["timestamp"])

            if since and ts <= since:
                continue

            if entry["rule_type"] not in rule_types:
                continue

            if tags:
                entry_tags = entry.get("tags", [])
                if not any(t in entry_tags for t in tags):
                    continue

            raw_rules.append(
                RawRule(
                    rule_type=entry["rule_type"],
                    name=entry["name"],
                    content=entry["content"],
                    event_id=entry["event_id"],
                    event_uuid=entry["event_uuid"],
                    misp_timestamp=ts,
                    tags=entry.get("tags", []),
                )
            )
        return raw_rules
