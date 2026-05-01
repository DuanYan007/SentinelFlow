from dataclasses import dataclass, field

from core.enums import ModuleStatus


@dataclass
class DynamicAnalysisResult:
    executed: bool = False
    environment: str = ""
    tools_used: list[str] = field(default_factory=list)
    execution_status: str = ModuleStatus.SKIPPED.value
    process_events: list[dict] = field(default_factory=list)
    file_events: list[dict] = field(default_factory=list)
    matched_features: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    score_breakdown: list[dict] = field(default_factory=list)
    summary: str = ""
    status: str = ModuleStatus.SKIPPED.value
    error: str | None = None

