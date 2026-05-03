from dataclasses import dataclass, field

from core.enums import ModuleStatus


@dataclass
class DynamicAnalysisResult:
    executed: bool = False
    environment: str = ""
    adapter_selected: str = ""
    adapter_candidates: list[str] = field(default_factory=list)
    input_artifact_path: str = ""
    tools_used: list[str] = field(default_factory=list)
    execution_status: str = ModuleStatus.SKIPPED.value
    process_events: list[dict] = field(default_factory=list)
    file_events: list[dict] = field(default_factory=list)
    artifact_schema_version: str = ""
    artifact_validation: dict = field(default_factory=dict)
    behavior_summary: dict = field(default_factory=dict)
    matched_features: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    score_breakdown: list[dict] = field(default_factory=list)
    summary: str = ""
    status: str = ModuleStatus.SKIPPED.value
    error: str | None = None
