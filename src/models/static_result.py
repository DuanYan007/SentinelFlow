from dataclasses import dataclass, field

from core.enums import ModuleStatus


@dataclass
class StaticAnalysisResult:
    executed: bool = False
    tools_used: list[str] = field(default_factory=list)
    pe_features: dict = field(default_factory=dict)
    import_features: dict = field(default_factory=dict)
    string_features: dict = field(default_factory=dict)
    matched_features: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    score_breakdown: list[dict] = field(default_factory=list)
    v2: dict = field(default_factory=dict)
    summary: str = ""
    status: str = ModuleStatus.SKIPPED.value
    error: str | None = None
