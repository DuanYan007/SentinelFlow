from dataclasses import dataclass, field


@dataclass
class StaticConfig:
    enabled_tools: list[str] = field(default_factory=lambda: ["pefile", "strings", "die"])
    enable_v2_output: bool = True
    entropy_threshold: float = 7.2
    high_entropy_section_count_threshold: int = 2
    strings_binary: str = "/usr/bin/strings"
    die_binary: str = ""
    rules_dir: str = "rules"
    section_rules_file: str = "static-section-rules.yaml"
    import_rules_file: str = "static-import-rules.yaml"
    string_keyword_sets: dict = field(default_factory=dict)
    score_weights: dict = field(
        default_factory=lambda: {"pe_score": 0.3, "import_score": 0.3, "string_score": 0.4}
    )
    medium_score_threshold: float = 0.30
    high_score_threshold: float = 0.60
