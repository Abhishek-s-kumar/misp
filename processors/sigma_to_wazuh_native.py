"""
Native Sigma -> Wazuh XML converter, walking pySigma's parsed rule model
directly (no official Wazuh backend exists in pySigma).

Scope (post-DNF upgrade):
- OR conditions distribute into disjunctive normal form -- each OR-alternative
  becomes its own Wazuh <rule>, all under one <group>. One Sigma rule can fan
  out into several Wazuh rules.
- AND conditions combine into <field> elements on the same rule. Same-field
  literals merge: positives via PCRE2 lookahead conjunction, negatives via
  alternation under one negate="yes".
- NOT is handled via De Morgan: NOT(A OR B) == NOT(A) AND NOT(B).
- Cartesian-product cap (500) on AND-distribution -- prevents pathological
  nested OR/AND from exploding into an unbounded number of rules.
- FIELD_MAP now loads from field_mappings.yaml at the repo root (falls back
  to a small built-in default if that file is missing/invalid).
- Anything still unsupported (field-less keyword match, non-string leaf
  values) raises NotImplementedError/ValueError -- caller (sigma_converter.py)
  turns that into SigmaConversionUnsupported. No silent/mock output here.
"""
from __future__ import annotations
import itertools
import math
import os
import re
from dataclasses import dataclass
from typing import Optional

import structlog
import yaml as _yaml
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

MAX_AND_CLAUSE_PRODUCT = 500
MAX_TOTAL_CLAUSES = 50  # cap on total Wazuh rules one Sigma rule can fan out to

# Repo-root field_mappings.yaml (this file lives at <repo_root>/processors/).
_FIELD_MAPPINGS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "field_mappings.yaml"
)

# Minimal built-in fallback, same as the original hardcoded FIELD_MAP.
_DEFAULT_FIELD_MAP: dict[str, str] = {
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "TargetFilename": "win.eventdata.targetFilename",
    "DestinationIp": "win.eventdata.destinationIp",
    "User": "win.eventdata.user",
}


def load_field_mappings(path: str = _FIELD_MAPPINGS_PATH) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _yaml.safe_load(f)
    except FileNotFoundError:
        log.warning("field_mappings_file_not_found", path=path)
        return dict(_DEFAULT_FIELD_MAP)
    if not isinstance(data, dict) or not data:
        log.warning("field_mappings_file_empty_or_invalid", path=path)
        return dict(_DEFAULT_FIELD_MAP)
    return {str(k): str(v) for k, v in data.items()}


FIELD_MAP: dict[str, str] = load_field_mappings()


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


def _merge_field_literals(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """Merge literals for the SAME Wazuh field within one AND-clause.
    Same polarity collapses (lookahead AND / alternation OR); a positive and a
    negated literal on the same field stay as two separate <field> elements."""
    result = [dict(lit) for lit in existing]
    for lit in incoming:
        same = next((e for e in result if e["negate"] == lit["negate"]), None)
        if same is None:
            result.append(dict(lit))
        elif lit["negate"]:
            same["pattern"] = f"(?:{same['pattern']})|(?:{lit['pattern']})"
        else:
            same["pattern"] = f"(?=.*{same['pattern']})(?=.*{lit['pattern']})"
    return result


def _and_clauses(clause_lists: list[list[dict]]) -> list[dict]:
    """AND together several DNF operands via cartesian product, capped."""
    product_size = math.prod(len(c) for c in clause_lists) if clause_lists else 1
    if product_size > MAX_AND_CLAUSE_PRODUCT:
        raise ValueError(
            f"AND clause cartesian product too large ({product_size} > "
            f"{MAX_AND_CLAUSE_PRODUCT}): nested OR/AND structure would explode "
            f"into too many rules. Simplify the condition."
        )
    result: list[dict] = []
    for combo in itertools.product(*clause_lists):
        merged: dict = {}
        for clause in combo:
            for field, literals in clause.items():
                if field in merged:
                    merged[field] = _merge_field_literals(merged[field], literals)
                else:
                    merged[field] = [dict(lit) for lit in literals]
        result.append(merged)
    return result


def evaluate_ast(node) -> list[dict]:
    """Recursive DNF walk. Returns list of OR-alternatives; each alternative
    maps a Wazuh field name to a list of {"pattern": str, "negate": bool}."""
    if isinstance(node, ConditionOR):
        result: list[dict] = []
        for arg in node.args:
            result.extend(evaluate_ast(arg))
        return result

    if isinstance(node, ConditionAND):
        args_eval = [evaluate_ast(arg) for arg in node.args]
        return _and_clauses(args_eval)

    if isinstance(node, ConditionNOT):
        child_evals = evaluate_ast(node.args[0])
        negated_operands: list[list[dict]] = []
        for clause in child_evals:
            alternatives = [
                {field: [{"pattern": lit["pattern"], "negate": not lit["negate"]}]}
                for field, lits in clause.items()
                for lit in lits
            ]
            if alternatives:
                negated_operands.append(alternatives)
        if not negated_operands:
            return [{}]
        return _and_clauses(negated_operands)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        wazuh_field = _map_field(node.field)
        pattern = _value_to_regex(node.value)
        return [{wazuh_field: [{"pattern": pattern, "negate": False}]}]

    if isinstance(node, ConditionValueExpression):
        raise NotImplementedError(
            "Unsupported Sigma construct: field-less keyword match would emit "
            "a rule with no <field> constraints, matching every event."
        )

    log.warning("sigma_condition_node_unhandled", node_type=type(node).__name__)
    raise NotImplementedError(f"Unsupported Sigma condition node: {type(node).__name__}")


def convert_rule(sigma_rule: SigmaRule, wazuh_level: int, rule_id: int) -> ConversionResult:
    try:
        conditions = sigma_rule.detection.parsed_condition
        if not conditions:
            return ConversionResult(None, True, "no parsed condition")

        clauses: list[dict] = []
        for cond in conditions:
            clauses.extend(evaluate_ast(cond.parsed))

        if not clauses:
            return ConversionResult(None, True, "condition produced no clauses")

        if len(clauses) > MAX_TOTAL_CLAUSES:
            return ConversionResult(
                None, True,
                f"condition fans out to {len(clauses)} Wazuh rules, exceeding "
                f"MAX_TOTAL_CLAUSES ({MAX_TOTAL_CLAUSES}); likely a large enumerated "
                f"OR list (e.g. unicode/character-class alternatives) rather than "
                f"genuine detection branching. Needs manual review/rewrite.",
            )

        rule_blocks = []
        for idx, fields in enumerate(clauses):
            if not fields:
                return ConversionResult(
                    None, True,
                    "clause has no field constraints (unsupported keyword-only condition)",
                )
            field_lines = []
            for field, literals in fields.items():
                for lit in literals:
                    negate_attr = ' negate="yes"' if lit["negate"] else ""
                    field_lines.append(
                        f'    <field name="{field}" type="pcre2"{negate_attr}>{lit["pattern"]}</field>'
                    )
            desc = sigma_rule.title if len(clauses) == 1 else f"{sigma_rule.title} (Part {idx + 1})"
            rule_blocks.append(
                f'  <rule id="{rule_id + idx}" level="{wazuh_level}">\n'
                + "\n".join(field_lines) + "\n"
                f"    <description>{desc}</description>\n"
                f"  </rule>"
            )

        xml = '<group name="sigma,misp,">\n' + "\n".join(rule_blocks) + "\n</group>"
        return ConversionResult(xml, False)

    except (NotImplementedError, ValueError) as e:
        return ConversionResult(None, True, str(e))
    except Exception as e:
        log.error("sigma_native_conversion_error", rule=sigma_rule.title, error=str(e))
        return ConversionResult(None, True, str(e))
