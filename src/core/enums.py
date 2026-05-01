from enum import Enum


class WorkflowState(str, Enum):
    INITIALIZED = "initialized"
    COMPLETED = "completed"
    COMPLETED_DEGRADED = "completed_degraded"
    FAILED_EARLY = "failed_early"


class ModuleStatus(str, Enum):
    SKIPPED = "skipped"
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    FATAL = "fatal"


class WorkflowStage(str, Enum):
    SAMPLE_INGEST = "sample_ingest"
    HASH_INTEL = "hash_intel"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    FINAL_VERDICT = "final_verdict"


class FinalLabel(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"

