"""
Sigma -> Wazuh XML conversion.

No official Wazuh backend exists for pySigma/sigma-cli, so conversion is done
natively by walking pySigma's parsed rule model directly. See
sigma_to_wazuh_native.py for the DNF/De Morgan field-mapping logic and its
documented scope limits.

Rules the native converter cannot translate soundly raise
SigmaConversionUnsupported -- caller (xml_merger.py) catches this and skips
the rule from the compiled ruleset with a logged reason, instead of emitting
a placeholder rule with no detection logic.
"""

from pathlib import Path
from typing import Optional

import structlog
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from processors.sigma_to_wazuh_native import convert_rule as _native_convert_rule

log = structlog.get_logger()

LEVEL_MAP = {"low": 3, "medium": 5, "high": 10, "critical": 15}

# Placeholder rule id for the pre-override XML. xml_merger.py always calls
# override_xml_rule_ids() with the real id from the Sigma YAML's
# custom.wazuh_rule_id field after this returns, so this value never
# reaches a deployed rule -- it exists only so the XML is well-formed
# while in transit.
_PLACEHOLDER_RULE_ID = 100000


class SigmaConversionUnsupported(Exception):
    """Raised when the native converter cannot soundly translate a Sigma rule."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def convert_sigma_to_wazuh(sigma_content: str, sigma_name: str) -> Optional[str]:
    """
    Convert a Sigma YAML rule to Wazuh XML format via native pySigma
    rule-object walking.

    Returns:
        Wazuh XML string on success.
        None only if the rule cannot be parsed as Sigma at all.
    Raises:
        SigmaConversionUnsupported if the rule parses but its condition logic
        cannot be soundly translated (caller should skip/quarantine it).
    """
    try:
        collection = SigmaCollection.from_yaml(sigma_content)
    except SigmaError as e:
        log.error("sigma_parse_error", rule=sigma_name, error=str(e))
        return None
    except Exception as e:
        log.error("sigma_parse_error_unexpected", rule=sigma_name, error=str(e))
        return None

    if not collection.rules:
        log.error("sigma_no_rules_in_file", rule=sigma_name)
        return None

    sigma_rule = collection.rules[0]
    level_str = str(sigma_rule.level).lower() if sigma_rule.level else "medium"
    wazuh_level = LEVEL_MAP.get(level_str, 5)

    result = _native_convert_rule(sigma_rule, wazuh_level, _PLACEHOLDER_RULE_ID)

    if result.xml is not None:
        log.info("sigma_native_conversion_success", rule=sigma_name)
        return result.xml

    log.warning(
        "sigma_native_conversion_unsupported",
        rule=sigma_name,
        reason=result.reason,
    )
    raise SigmaConversionUnsupported(result.reason or "unsupported condition logic")
