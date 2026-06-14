from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class RawRule:
    rule_type: str        # "yara" | "sigma" | "wazuh"
    name: str             # e.g., "win_susp_powershell.yml"
    content: str          # Raw rule string
    event_id: int
    event_uuid: str
    misp_timestamp: datetime
    tags: List[str]

class MISPRuleProvider(ABC):
    @abstractmethod
    def fetch_rules(
        self,
        rule_types: List[str],
        tags: List[str],
        since: Optional[datetime] = None
    ) -> List[RawRule]:
        """Return a list of raw Rules. Incremental if since is provided."""
        pass
