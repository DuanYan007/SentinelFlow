from dataclasses import dataclass, field


@dataclass
class AgentDynamicRequest:
    execution_mode: str = "safe_replay"
    allow_sample_execution: bool = False
    preferred_adapter: str = ""
    fallback_adapters: list[str] = field(default_factory=list)
    input_artifact_path: str = ""
    continue_on_unavailable: bool = True


@dataclass
class AgentExecutionState:
    current_strategy: str = ""
    active_stage: str = ""
    stage_plans: dict[str, dict] = field(default_factory=dict)
    dynamic_request: AgentDynamicRequest = field(default_factory=AgentDynamicRequest)
