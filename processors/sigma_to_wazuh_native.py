"""
Native Sigma -> Wazuh XML converter, walking pySigma's parsed rule model
directly (no official Wazuh backend exists in pySigma, so we don't route
through `sigma convert --target`).

Scope:
- AND-only field combination (implicit AND across Wazuh <field> children).
  Covers a single `selection` block or `all of selection*` conditions.
- Multiple values on one field (Sigma list = OR) -> regex alternation.
- Cross-field OR / NOT conditions are NOT converted -- they are flagged
  needs_manual_review so they never silently become dead or wrong rules.
- FIELD_MAP is site-specific and incomplete by design -- fill in as you
  confirm your Wazuh decoder field names. Unmapped fields pass through
  unchanged with a logged warning.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

import structlog
from sigma.rule import SigmaRule
from sigma.conditions import (
    ConditionAND,
    ConditionOR,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
    ConditionValueExpression,
)
from sigma.types import SigmaString, SigmaNumber, SigmaBool, SigmaRegularExpression

log = structlog.get_logger()

# Sigma taxonomy field name -> your Wazuh decoded field name.
# TODO: confirm each against your actual decoders before trusting matches.
FIELD_MAP: dict[str, str] = {
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "TargetFilename": "win.eventdata.targetFilename",
    "DestinationIp": "win.eventdata.destinationIp",
    "User": "win.eventdata.user",
}


@dataclass
class ConversionResult:
    xml: Optional[str]
    needs_manual_review: bool
    reason: Optional[str] = None


def _map_field(field: str) -> str:
    mapped = FIELD_MAP.get(field)
    if mapped is None:
        log.warning("sigma_field_unmapped", field=field)
        return field
    return mapped


def _value_to_regex(value) -> str:
    if isinstance(value, SigmaString):
        s = str(value)
        pattern = re.escape(s).replace(r"\*", ".*").replace(r"\?", ".")
        return f"^{pattern}$"
    if isinstance(value, SigmaRegularExpression):
        return str(value.regexp)
    if isinstance(value, (SigmaNumber, SigmaBool)):
        return f"^{re.escape(str(value))}$"
    return f"^{re.escape(str(value))}$"


def _field_item_to_xml(field: str, values: list, negate: bool = False) -> str:
    wazuh_field = _map_field(field)
    if len(values) == 1:
        regex = _value_to_regex(values[0])
    else:
        alts = "|".join(_value_to_regex(v).strip("^$") for v in values)
        regex = f"^({alts})$"
    negate_attr = ' negate="yes"' if negate else ""
    return f'    <field name="{wazuh_field}" type="pcre2"{negate_attr}>{regex}</field>'


def _negatable_field_extraction(node) -> "tuple[str, list] | None":
    """
    Extracts (field, values) from a node if it is simple enough to express
    as a single negated Wazuh <field negate="yes">. Handles a single
    FieldEqualsValueExpression, or an OR of FieldEqualsValueExpression nodes
    that all share the same field (e.g. "not 1 of filter_main_*" where the
    filter selections are same-field alternatives). Returns None -- caller
    must flag for manual review -- for anything else (cross-field OR, nested
    AND, etc.), since those cannot be safely collapsed into one field.
    """
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return node.field, [node.value]
    if isinstance(node, ConditionOR):
        field_names = set()
        values = []
        for arg in node.args:
            if not isinstance(arg, ConditionFieldEqualsValueExpression):
                return None
            field_names.add(arg.field)
            values.append(arg.value)
        if len(field_names) == 1:
            return next(iter(field_names)), values
    return None


def _walk_condition(node) -> tuple[list[str], bool]:
    """Returns (field xml lines, needs_manual_review)."""
    if isinstance(node, ConditionAND):
        lines: list[str] = []
        review = False
        for arg in node.args:
            if isinstance(arg, ConditionNOT):
                negated = _negatable_field_extraction(arg.args[0])
                if negated is not None:
                    field, values = negated
                    lines.append(_field_item_to_xml(field, values, negate=True))
                    continue
                review = True
                continue
            sub_lines, sub_review = _walk_condition(arg)
            lines.extend(sub_lines)
            review = review or sub_review
        return lines, review

    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [_field_item_to_xml(node.field, [node.value])], False

    if isinstance(node, ConditionOR):
        # Sigma's default list semantics are OR (e.g. CommandLine|contains: [a, b, c]
        # without |all). If every branch is a FieldEqualsValueExpression on the SAME
        # field, this collapses cleanly into one Wazuh <field> with regex alternation.
        # Cross-field OR (different field names) cannot collapse into Wazuh's AND-only
        # field schema -- that case still correctly falls through to needs_manual_review.
        field_names = set()
        values = []
        all_simple = True
        for arg in node.args:
            if isinstance(arg, ConditionFieldEqualsValueExpression):
                field_names.add(arg.field)
                values.append(arg.value)
            else:
                all_simple = False
                break
        if all_simple and len(field_names) == 1:
            field = next(iter(field_names))
            return [_field_item_to_xml(field, values)], False
        return [], True

    if isinstance(node, (ConditionNOT, ConditionValueExpression)):
        # Not representable as a single Wazuh rule -- flag, don't fake.
        return [], True

    log.warning("sigma_condition_node_unhandled", node_type=type(node).__name__)
    return [], True


def convert_rule(sigma_rule: SigmaRule, wazuh_level: int, rule_id: int) -> ConversionResult:
    try:
        conditions = sigma_rule.detection.parsed_condition
        if not conditions:
            return ConversionResult(None, True, "no parsed condition")

        all_lines: list[str] = []
        any_review = False
        for cond in conditions:
            tree = cond.parsed
            lines, review = _walk_condition(tree)
            all_lines.extend(lines)
            any_review = any_review or review

        if any_review or not all_lines:
            return ConversionResult(
                None, True,
                "condition uses OR/NOT or is otherwise unsupported; needs manual rule split",
            )

        fields_xml = "\n".join(all_lines)
        xml = (
            f'<group name="sigma,misp,">\n'
            f'  <rule id="{rule_id}" level="{wazuh_level}">\n'
            f'{fields_xml}\n'
            f"    <description>{sigma_rule.title}</description>\n"
            f"  </rule>\n"
            f"</group>"
        )
        return ConversionResult(xml, False)

    except Exception as e:
        log.error("sigma_native_conversion_error", rule=sigma_rule.title, error=str(e))
        return ConversionResult(None, True, str(e))
