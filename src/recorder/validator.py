from dataclasses import dataclass, field

from models.analysis_context import AnalysisContext


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_analysis_context(context: AnalysisContext) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not context.runtime.workflow_id:
        errors.append("runtime.workflow_id is required")
    if not context.runtime.start_time:
        errors.append("runtime.start_time is required")
    if context.verdict.final_label not in {"malicious", "suspicious", "benign"}:
        errors.append("verdict.final_label must be one of malicious/suspicious/benign")
    if context.workflow_status.status == "":
        errors.append("workflow_status.status is required")
    if context.sample.file_path == "":
        warnings.append("sample.file_path is empty")

    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)


def _require_mapping(data: dict, key: str, errors: list[str]) -> dict:
    value = data.get(key)
    if not isinstance(value, dict):
        errors.append(f"{key} must be an object")
        return {}
    return value


def _require_list(data: dict, key: str, errors: list[str]) -> list:
    value = data.get(key)
    if not isinstance(value, list):
        errors.append(f"{key} must be a list")
        return []
    return value


def validate_result_dict(data: dict) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(data, dict):
        return ValidationResult(valid=False, errors=["result root must be an object"])

    sample = _require_mapping(data, "sample", errors)
    threat_intel = _require_mapping(data, "threat_intel", errors)
    agent_execution = _require_mapping(data, "agent_execution", errors)
    _require_list(data, "agent_trace", errors)
    static_analysis = _require_mapping(data, "static_analysis", errors)
    verdict = _require_mapping(data, "verdict", errors)
    runtime = _require_mapping(data, "runtime", errors)
    workflow_status = _require_mapping(data, "workflow_status", errors)

    if sample and not sample.get("file_path"):
        warnings.append("sample.file_path is empty")
    if sample and not sample.get("sha256"):
        warnings.append("sample.sha256 is empty")
    if threat_intel and "status" not in threat_intel:
        errors.append("threat_intel.status is required")
    if agent_execution:
        if "stage_plans" not in agent_execution or not isinstance(agent_execution.get("stage_plans"), dict):
            errors.append("agent_execution.stage_plans must be an object")
    if static_analysis and "status" not in static_analysis:
        errors.append("static_analysis.status is required")
    if static_analysis and "v2" in static_analysis:
        v2 = static_analysis.get("v2")
        if not isinstance(v2, dict):
            errors.append("static_analysis.v2 must be an object")
        else:
            if not v2.get("schema_version"):
                errors.append("static_analysis.v2.schema_version is required")
            if "tool_outputs" not in v2 or not isinstance(v2.get("tool_outputs"), dict):
                errors.append("static_analysis.v2.tool_outputs must be an object")
            if "normalized_features" not in v2 or not isinstance(v2.get("normalized_features"), dict):
                errors.append("static_analysis.v2.normalized_features must be an object")
            if "score_breakdown" not in v2 or not isinstance(v2.get("score_breakdown"), dict):
                errors.append("static_analysis.v2.score_breakdown must be an object")
            if "summary" not in v2 or not isinstance(v2.get("summary"), dict):
                errors.append("static_analysis.v2.summary must be an object")
            if "risk_score" in v2 and not isinstance(v2.get("risk_score"), (int, float)):
                errors.append("static_analysis.v2.risk_score must be numeric")
    if verdict:
        if verdict.get("final_label") not in {"malicious", "suspicious", "benign"}:
            errors.append("verdict.final_label must be malicious/suspicious/benign")
        if not isinstance(verdict.get("decision_basis"), list):
            errors.append("verdict.decision_basis must be a list")
    if runtime and not runtime.get("workflow_id"):
        errors.append("runtime.workflow_id is required")
    if workflow_status and not workflow_status.get("status"):
        errors.append("workflow_status.status is required")

    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)
