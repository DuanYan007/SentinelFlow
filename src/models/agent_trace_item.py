from dataclasses import dataclass, field


@dataclass
class AgentTraceItem:
    step_id: int = 0
    stage: str = ""
    decision: str = ""
    reason: str = ""
    input_summary: dict = field(default_factory=dict)
    used_skill: str = ""
    used_tool: str = ""
    confidence: float = 0.0
    timestamp: str = ""

