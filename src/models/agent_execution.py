from dataclasses import dataclass, field


@dataclass
class AgentExecutionState:
    current_strategy: str = ""
    active_stage: str = ""
    stage_plans: dict[str, dict] = field(default_factory=dict)
