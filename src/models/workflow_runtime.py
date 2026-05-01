from dataclasses import dataclass

from core.constants import DEFAULT_PHASE_NAME
from core.ids import generate_workflow_id
from core.time_utils import now_iso


@dataclass
class WorkflowRuntime:
    workflow_id: str
    batch_id: str = ""
    start_time: str = ""
    end_time: str = ""
    duration_sec: float = 0.0
    phase: str = DEFAULT_PHASE_NAME
    rerun_count: int = 0
    final_attempt: int = 1
    notes: str = ""


def create_default_runtime(phase_name: str = DEFAULT_PHASE_NAME) -> WorkflowRuntime:
    return WorkflowRuntime(
        workflow_id=generate_workflow_id(),
        start_time=now_iso(),
        phase=phase_name,
    )

