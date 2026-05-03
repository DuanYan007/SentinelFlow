from dataclasses import asdict, dataclass, field

from core.constants import DEFAULT_PHASE_NAME
from .agent_execution import AgentExecutionState
from .agent_trace_item import AgentTraceItem
from .dynamic_result import DynamicAnalysisResult
from .sample_info import SampleInfo
from .static_result import StaticAnalysisResult
from .threat_intel_result import ThreatIntelResult
from .verdict_result import VerdictResult
from .workflow_runtime import WorkflowRuntime, create_default_runtime
from .workflow_status import WorkflowStatus, create_default_workflow_status


@dataclass
class AnalysisContext:
    sample: SampleInfo
    threat_intel: ThreatIntelResult
    agent_execution: AgentExecutionState = field(default_factory=AgentExecutionState)
    agent_trace: list[AgentTraceItem] = field(default_factory=list)
    static_analysis: StaticAnalysisResult = field(default_factory=StaticAnalysisResult)
    dynamic_analysis: DynamicAnalysisResult = field(default_factory=DynamicAnalysisResult)
    verdict: VerdictResult = field(default_factory=VerdictResult)
    runtime: WorkflowRuntime = field(default_factory=create_default_runtime)
    workflow_status: WorkflowStatus = field(default_factory=create_default_workflow_status)

    def to_dict(self) -> dict:
        return asdict(self)


def create_empty_analysis_context(sample_path: str, phase_name: str = DEFAULT_PHASE_NAME) -> AnalysisContext:
    runtime = create_default_runtime(phase_name)
    sample = SampleInfo(file_path=sample_path, submitted_at=runtime.start_time)
    return AnalysisContext(
        sample=sample,
        threat_intel=ThreatIntelResult(),
        runtime=runtime,
        workflow_status=create_default_workflow_status(),
    )
