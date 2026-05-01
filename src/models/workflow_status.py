from dataclasses import dataclass

from core.enums import WorkflowState


@dataclass
class WorkflowStatus:
    status: str = WorkflowState.INITIALIZED.value
    fatal: bool = False
    error_code: str = ""
    message: str = ""


def create_default_workflow_status() -> WorkflowStatus:
    return WorkflowStatus()

