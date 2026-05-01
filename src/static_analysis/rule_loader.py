from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_RULES_DIRNAME = "rules"
DEFAULT_SECTION_RULES_FILENAME = "static-section-rules.yaml"
DEFAULT_IMPORT_RULES_FILENAME = "static-import-rules.yaml"


@dataclass
class RuleCategory:
    id: str
    enabled: bool = True
    risk_weight: float = 0.0
    description: str = ""


@dataclass
class RuleDefinition:
    rule_id: str
    category: str
    enabled: bool = True
    risk_weight: float = 0.0
    match: dict = field(default_factory=dict)
    note: str = ""
    tags: list[str] = field(default_factory=list)
    extensions: dict = field(default_factory=dict)


@dataclass
class RuleSet:
    version: str
    enabled: bool = True
    rule_set_name: str = ""
    description: str = ""
    defaults: dict = field(default_factory=dict)
    categories: dict[str, RuleCategory] = field(default_factory=dict)
    rules: list[RuleDefinition] = field(default_factory=list)
    extensions: dict = field(default_factory=dict)
    source_path: str = ""


@dataclass
class StaticRuleBundle:
    section_rules: RuleSet
    import_rules: RuleSet


def _require_yaml() -> None:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load static-analysis rule files")


def _read_yaml(path: Path) -> dict:
    _require_yaml()
    if not path.exists():
        raise FileNotFoundError(f"rule file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"rule file root must be an object: {path}")
    return data


def _load_categories(data: dict, source_path: Path) -> dict[str, RuleCategory]:
    raw_categories = data.get("categories", [])
    if not isinstance(raw_categories, list):
        raise ValueError(f"categories must be a list: {source_path}")

    categories: dict[str, RuleCategory] = {}
    for item in raw_categories:
        if not isinstance(item, dict):
            raise ValueError(f"category entry must be an object: {source_path}")
        category_id = str(item.get("id", "")).strip()
        if not category_id:
            raise ValueError(f"category.id is required: {source_path}")
        categories[category_id] = RuleCategory(
            id=category_id,
            enabled=bool(item.get("enabled", True)),
            risk_weight=float(item.get("risk_weight", 0.0) or 0.0),
            description=str(item.get("description", "")),
        )
    return categories


def _load_rules(data: dict, categories: dict[str, RuleCategory], source_path: Path) -> list[RuleDefinition]:
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"rules must be a list: {source_path}")

    rules: list[RuleDefinition] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError(f"rule entry must be an object: {source_path}")
        rule_id = str(item.get("rule_id", "")).strip()
        category = str(item.get("category", "")).strip()
        if not rule_id:
            raise ValueError(f"rule.rule_id is required: {source_path}")
        if not category:
            raise ValueError(f"rule.category is required for {rule_id}: {source_path}")
        if category not in categories:
            raise ValueError(f"rule.category '{category}' is undefined for {rule_id}: {source_path}")

        match_block = item.get("match", {})
        if not isinstance(match_block, dict):
            raise ValueError(f"rule.match must be an object for {rule_id}: {source_path}")

        tags = item.get("tags", [])
        if not isinstance(tags, list):
            raise ValueError(f"rule.tags must be a list for {rule_id}: {source_path}")

        extensions = item.get("extensions", {})
        if not isinstance(extensions, dict):
            raise ValueError(f"rule.extensions must be an object for {rule_id}: {source_path}")

        rules.append(
            RuleDefinition(
                rule_id=rule_id,
                category=category,
                enabled=bool(item.get("enabled", True)),
                risk_weight=float(item.get("risk_weight", 0.0) or 0.0),
                match=match_block,
                note=str(item.get("note", "")),
                tags=[str(tag) for tag in tags],
                extensions=extensions,
            )
        )
    return rules


def load_rule_set(path: str | Path) -> RuleSet:
    source_path = Path(path)
    data = _read_yaml(source_path)
    categories = _load_categories(data, source_path)
    rules = _load_rules(data, categories, source_path)

    defaults = data.get("defaults", {})
    extensions = data.get("extensions", {})
    if not isinstance(defaults, dict):
        raise ValueError(f"defaults must be an object: {source_path}")
    if not isinstance(extensions, dict):
        raise ValueError(f"extensions must be an object: {source_path}")

    version = str(data.get("version", "")).strip()
    if not version:
        raise ValueError(f"version is required: {source_path}")

    return RuleSet(
        version=version,
        enabled=bool(data.get("enabled", True)),
        rule_set_name=str(data.get("rule_set_name", "")),
        description=str(data.get("description", "")),
        defaults=defaults,
        categories=categories,
        rules=rules,
        extensions=extensions,
        source_path=str(source_path),
    )


def resolve_rules_dir(config_dir: str | Path) -> Path:
    return Path(config_dir) / DEFAULT_RULES_DIRNAME


def load_static_rule_bundle(config_dir: str | Path) -> StaticRuleBundle:
    rules_dir = resolve_rules_dir(config_dir)
    return StaticRuleBundle(
        section_rules=load_rule_set(rules_dir / DEFAULT_SECTION_RULES_FILENAME),
        import_rules=load_rule_set(rules_dir / DEFAULT_IMPORT_RULES_FILENAME),
    )
