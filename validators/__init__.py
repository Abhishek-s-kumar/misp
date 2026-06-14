"""
validators package — Detection rule syntax validation.

Exposes a unified RuleValidator that dispatches to the correct engine
based on rule_type.
"""

import structlog

from collector.base import RawRule
from validators.yara_validator import ValidationResult, validate_yara
from validators.sigma_validator import validate_sigma
from validators.wazuh_validator import validate_wazuh

log = structlog.get_logger()

__all__ = [
    "RuleValidator",
    "ValidationResult",
    "validate_yara",
    "validate_sigma",
    "validate_wazuh",
]


class RuleValidator:
    """
    Dispatches validation to the correct engine based on rule type.
    """

    _dispatch = {
        "yara": validate_yara,
        "sigma": validate_sigma,
        "wazuh": validate_wazuh,
    }

    def validate(self, rule: RawRule) -> ValidationResult:
        validator_fn = self._dispatch.get(rule.rule_type)
        if validator_fn is None:
            return ValidationResult(
                valid=False,
                errors=[f"Unknown rule type: {rule.rule_type}"],
            )

        log.info(
            "validating_rule",
            rule_name=rule.name,
            rule_type=rule.rule_type,
        )
        result = validator_fn(rule.content)
        log.info(
            "validation_complete",
            rule_name=rule.name,
            valid=result.valid,
            errors=result.errors,
        )
        return result
