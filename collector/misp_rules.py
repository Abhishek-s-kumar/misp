import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import structlog

from collector.base import MISPRuleProvider, RawRule
from collector.mock_provider import MockMISPRuleProvider
from collector.pymisp_provider import PyMISPRuleProvider

log = structlog.get_logger()


def get_rule_provider() -> MISPRuleProvider:
    """Factory: returns MockMISPRuleProvider or PyMISPRuleProvider based on env."""
    if os.environ.get("MISP_PROVIDER", "mock").lower() == "real":
        return PyMISPRuleProvider()
    return MockMISPRuleProvider()


class MISPRuleCollector:
    """
    Orchestrates rule ingestion from MISP.
    Tracks last sync timestamp in a state file for incremental pulls.
    Writes fetched rules to rules/pending/ in the repository.
    """

    def __init__(self, provider: MISPRuleProvider, state_file: Path):
        self.provider = provider
        self.state_file = state_file

    def _load_last_sync(self) -> Optional[datetime]:
        if not self.state_file.exists():
            return None
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "last_rule_sync_time" in data:
                    return datetime.fromisoformat(data["last_rule_sync_time"])
        except Exception as e:
            log.warning("failed_to_load_rule_sync_state", error=str(e))
        return None

    def _save_last_sync(self, dt: datetime) -> None:
        try:
            # Preserve existing state file data (e.g. IOC sync timestamps)
            existing = {}
            if self.state_file.exists():
                with open(self.state_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)

            existing["last_rule_sync_time"] = dt.isoformat()

            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(existing, f)
        except Exception as e:
            log.error("failed_to_save_rule_sync_state", error=str(e))

    def pull(
        self,
        rule_types: List[str],
        tags: List[str],
        full_pull: bool = False,
        since_override: Optional[datetime] = None,
    ) -> List[RawRule]:
        """Pull rules from MISP, update state, and return the raw list."""
        if since_override:
            since = since_override
        else:
            since = None if full_pull else self._load_last_sync()

        log.info(
            "starting_misp_rule_pull",
            provider=self.provider.__class__.__name__,
            since=since,
        )
        raw_rules = self.provider.fetch_rules(
            rule_types=rule_types, tags=tags, since=since
        )
        log.info("misp_rule_pull_results", count=len(raw_rules))

        self._save_last_sync(datetime.now(timezone.utc))
        return raw_rules

