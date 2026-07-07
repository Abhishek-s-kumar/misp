"""
Sigma -> Wazuh XML conversion.

No official Wazuh backend exists for pySigma/sigma-cli (verified via
`sigma plugin list` -- Wazuh is absent from all registered backends), so
conversion is done natively by walking pySigma's parsed rule model
directly. See sigma_to_wazuh_native.py for the AND-only field-mapping
logic and its documented scope limits.

Mock conversion remains ONLY as a last-resort fallback for rules that
fail to parse at all, and is clearly tagged in both the log and the
returned XML's description so it can never be mistaken for a real
detection in dashboards or audits.
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


def convert_sigma_to_wazuh(
    sigma_content: str, sigma_name: str
) -> Optional[str]:
    """
    Convert a Sigma YAML rule to Wazuh XML format via native pySigma
    rule-object walking.

    Args:
        sigma_content: Raw Sigma YAML rule content.
        sigma_name: Filename of the Sigma rule (for logging).

    Returns:
        Wazuh XML string if conversion succeeds (native or mock
        fallback), None only if the rule cannot be parsed as Sigma at all.
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
        message="falling back to mock XML -- rule has NO detection logic, needs manual conversion",
    )
    return _mock_sigma_to_wazuh(sigma_content, sigma_name)


def _mock_sigma_to_wazuh(sigma_content: str, sigma_name: str) -> str:
    """
    Fallback for rules the native converter cannot handle (OR/NOT logic,
    unparseable structure). Deliberately tagged '[NEEDS MANUAL REVIEW -
    NO DETECTION LOGIC]' in the description so this can never be confused
    with a real, firing rule in Wazuh's dashboard or rule count.
    """
    import yaml

    try:
        sigma = yaml.safe_load(sigma_content)
    except Exception:
        sigma = {}
    title = sigma.get("title", sigma_name) if isinstance(sigma, dict) else sigma_name
    level = sigma.get("level", "medium") if isinstance(sigma, dict) else "medium"
    wazuh_level = LEVEL_MAP.get(level, 5)

    xml = (
        f'<group name="sigma,misp,needs_review,">\n'
        f'  <rule id="{_PLACEHOLDER_RULE_ID}" level="{wazuh_level}">\n'
        f"    <description>{title} [NEEDS MANUAL REVIEW - NO DETECTION LOGIC]</description>\n"
        f"  </rule>\n"
        f"</group>"
    )
    log.warning("sigma_mock_conversion_used", rule=sigma_name)
    return xml
