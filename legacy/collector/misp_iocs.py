import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from collector.base import MISPProvider, RawIOC
from collector.mock_provider import MockMISPProvider
from collector.pymisp_provider import PyMISPProvider
import structlog

log = structlog.get_logger()

def get_provider() -> MISPProvider:
    if os.environ.get("MISP_PROVIDER", "mock").lower() == "real":
        return PyMISPProvider()
    return MockMISPProvider()

class MISPIOCCollector:
    """
    Pulls IOC attributes from the chosen MISP provider.
    Tracks last_sync_time in a state file for incremental syncs.
    """
    def __init__(self, provider: MISPProvider, state_file: Path):
        self.provider = provider
        self.state_file = state_file

    def _load_last_sync(self) -> Optional[datetime]:
        if not self.state_file.exists():
            return None
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "last_sync_time" in data:
                    return datetime.fromisoformat(data["last_sync_time"])
        except Exception as e:
            log.warning("failed_to_load_sync_state", error=str(e))
        return None

    def _save_last_sync(self, dt: datetime) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump({"last_sync_time": dt.isoformat()}, f)
        except Exception as e:
            log.error("failed_to_save_sync_state", error=str(e))

    def pull(
        self,
        ioc_types: List[str],
        tags: List[str],
        full_pull: bool = False
    ) -> List[RawIOC]:
        since = None if full_pull else self._load_last_sync()
        
        log.info("starting_misp_pull", provider=self.provider.__class__.__name__, since=since)
        raw_iocs = self.provider.fetch_iocs(ioc_types=ioc_types, tags=tags, since=since)
        log.info("misp_pull_results", count=len(raw_iocs))
        
        self._save_last_sync(datetime.now(timezone.utc))
        return raw_iocs
