from dataclasses import dataclass, field

from core.constants import DEFAULT_PHASE_NAME


@dataclass
class BatchSummary:
    batch_id: str = ""
    runtime: dict = field(default_factory=dict)
    input_stats: dict = field(default_factory=dict)
    workflow_stats: dict = field(default_factory=dict)
    label_stats: dict = field(default_factory=dict)
    module_stats: dict = field(default_factory=dict)
    failure_stats: dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)
    phase: str = DEFAULT_PHASE_NAME

