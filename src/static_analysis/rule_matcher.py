from __future__ import annotations

import re
from dataclasses import dataclass, is_dataclass

from .rule_loader import RuleDefinition, RuleSet


@dataclass
class RuleMatchResult:
    rule_id: str
    category: str
    risk_weight: float
    matched: bool
    reason: str = ""


def _to_mapping(candidate) -> dict:
    if isinstance(candidate, dict):
        return candidate
    if is_dataclass(candidate):
        return candidate.__dict__
    return getattr(candidate, "__dict__", {})


def _get_field_value(candidate, field_name: str):
    if isinstance(candidate, dict):
        return candidate.get(field_name)
    return getattr(candidate, field_name, None)


def _resolve_ref(rule_set: RuleSet, ref_path: str):
    if not ref_path:
        return None
    parts = ref_path.split(".")
    current = {"defaults": rule_set.defaults}
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _normalize_text(value, case_insensitive: bool) -> str:
    text = "" if value is None else str(value)
    return text.lower() if case_insensitive else text


def _match_scalar_condition(condition: dict, candidate, rule_set: RuleSet) -> tuple[bool, str]:
    field_name = condition.get("field", "")
    operator = condition.get("operator", "")
    case_insensitive = bool(condition.get("case_insensitive", False))
    field_value = _get_field_value(candidate, field_name)

    threshold = condition.get("threshold")
    if "threshold_ref" in condition:
        threshold = _resolve_ref(rule_set, str(condition.get("threshold_ref", "")))

    values = condition.get("values")
    if "values_ref" in condition:
        values = _resolve_ref(rule_set, str(condition.get("values_ref", "")))

    combos = condition.get("combos")
    if "combos_ref" in condition:
        combos = _resolve_ref(rule_set, str(condition.get("combos_ref", "")))

    if operator == "eq":
        return field_value == threshold, f"{field_name} == {threshold}"
    if operator == "lte":
        return field_value is not None and field_value <= threshold, f"{field_name} <= {threshold}"
    if operator == "gte":
        return field_value is not None and field_value >= threshold, f"{field_name} >= {threshold}"
    if operator == "contains_all":
        haystack = field_value or []
        matched = isinstance(haystack, list) and all(item in haystack for item in (values or []))
        return matched, f"{field_name} contains all {values or []}"
    if operator == "in_ref":
        normalized_value = _normalize_text(field_value, case_insensitive)
        normalized_values = {_normalize_text(item, case_insensitive) for item in (values or [])}
        return normalized_value in normalized_values, f"{field_name} in ref set"
    if operator == "contains_combo_ref":
        haystack = field_value or []
        if not isinstance(haystack, list):
            return False, f"{field_name} is not a list"
        haystack_set = {str(item) for item in haystack}
        for combo in combos or []:
            combo_parts = {part.strip() for part in str(combo).split("+") if part.strip()}
            if combo_parts and combo_parts.issubset(haystack_set):
                return True, f"{field_name} contains combo {combo}"
        return False, f"{field_name} does not contain any combo"
    return False, f"unsupported operator: {operator}"


def _match_name_block(block: dict, candidate_value: str) -> bool:
    if not isinstance(block, dict):
        return False
    value = candidate_value or ""

    exact = block.get("exact", [])
    if isinstance(exact, list) and any(value.lower() == str(item).lower() for item in exact):
        return True

    prefixes = block.get("prefix", [])
    if isinstance(prefixes, list) and any(value.startswith(str(item)) for item in prefixes):
        return True

    regexes = block.get("regex", [])
    if isinstance(regexes, list):
        for pattern in regexes:
            try:
                if re.search(str(pattern), value):
                    return True
            except re.error:
                continue

    return False


def _match_import_condition(match_block: dict, candidate) -> tuple[bool, str]:
    candidate_map = _to_mapping(candidate)
    dll_value = str(candidate_map.get("dll", ""))
    api_value = str(candidate_map.get("api", ""))

    dlls_block = match_block.get("dlls", {})
    apis_block = match_block.get("apis", {})

    dll_matched = _match_name_block(dlls_block, dll_value) if dlls_block else True
    api_matched = _match_name_block(apis_block, api_value) if apis_block else True
    return dll_matched and api_matched, f"dll={dll_value}, api={api_value}"


def _evaluate_match_block(match_block: dict, candidate, rule_set: RuleSet) -> tuple[bool, str]:
    if "any_of" in match_block:
        conditions = match_block.get("any_of", [])
        if not isinstance(conditions, list):
            return False, "any_of must be a list"
        reasons: list[str] = []
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            matched, reason = _match_scalar_condition(condition, candidate, rule_set)
            reasons.append(reason)
            if matched:
                return True, reason
        return False, "; ".join(reasons) or "no any_of condition matched"

    if "field" in match_block and "operator" in match_block:
        return _match_scalar_condition(match_block, candidate, rule_set)

    if "dlls" in match_block or "apis" in match_block:
        return _match_import_condition(match_block, candidate)

    return False, "unsupported match block"


def match_rule(rule: RuleDefinition, candidate, rule_set: RuleSet) -> RuleMatchResult:
    if not rule.enabled or not rule_set.enabled:
        return RuleMatchResult(
            rule_id=rule.rule_id,
            category=rule.category,
            risk_weight=rule.risk_weight,
            matched=False,
            reason="rule or rule set disabled",
        )

    matched, reason = _evaluate_match_block(rule.match, candidate, rule_set)
    return RuleMatchResult(
        rule_id=rule.rule_id,
        category=rule.category,
        risk_weight=rule.risk_weight or rule_set.defaults.get("risk_weight", 0.0),
        matched=matched,
        reason=reason,
    )


def match_rules(rule_set: RuleSet, candidates: list) -> dict[int, list[RuleMatchResult]]:
    results: dict[int, list[RuleMatchResult]] = {}
    for index, candidate in enumerate(candidates):
        matches: list[RuleMatchResult] = []
        for rule in rule_set.rules:
            match_result = match_rule(rule, candidate, rule_set)
            if match_result.matched:
                matches.append(match_result)
        results[index] = matches
    return results
