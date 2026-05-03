from __future__ import annotations

from config.loader import RuntimeConfigBundle
from core.enums import ModuleStatus
from models.analysis_context import AnalysisContext
from .adapters import select_dynamic_adapter_candidates


def _build_behavior_summary(process_events: list[dict], file_events: list[dict]) -> dict:
    targeted_extensions: list[str] = []
    for event in file_events:
        values = event.get("target_extensions") or []
        if isinstance(values, list):
            targeted_extensions.extend(str(value) for value in values if value)
    return {
        "process_event_count": len(process_events),
        "file_event_count": len(file_events),
        "suspicious_spawn_count": sum(1 for event in process_events if event.get("suspicious_spawn")),
        "high_frequency_write_count": sum(1 for event in file_events if event.get("high_frequency_write")),
        "totals": {
            "created": sum(int(event.get("created_count", 0)) for event in file_events),
            "modified": sum(int(event.get("modified_count", 0)) for event in file_events),
            "renamed": sum(int(event.get("renamed_count", 0)) for event in file_events),
        },
        "targeted_extensions": sorted(set(targeted_extensions)),
    }


def _normalize_features(process_events: list[dict], file_events: list[dict], bundle: RuntimeConfigBundle) -> list[str]:
    features: list[str] = []
    if process_events:
        features.append("process_execution_observed")
    for event in process_events:
        if event.get("suspicious_spawn"):
            features.append("suspicious_child_process_spawn")
            break
    totals = {
        "created": sum(int(event.get("created_count", 0)) for event in file_events),
        "modified": sum(int(event.get("modified_count", 0)) for event in file_events),
        "renamed": sum(int(event.get("renamed_count", 0)) for event in file_events),
    }
    if totals["created"] >= bundle.dynamic_analysis.bulk_create_threshold:
        features.append("bulk_file_create")
    if totals["modified"] >= bundle.dynamic_analysis.bulk_modify_threshold:
        features.append("bulk_file_modify")
    if totals["renamed"] >= bundle.dynamic_analysis.bulk_rename_threshold:
        features.append("bulk_file_rename")
    if any(event.get("high_frequency_write") for event in file_events):
        features.append("high_frequency_write")
    if any(event.get("target_extensions") for event in file_events):
        features.append("targeted_user_file_extensions")
    return sorted(set(features))


def _score_dynamic_features(features: list[str]) -> tuple[float, list[dict]]:
    weights = {
        "bulk_file_rename": 0.30,
        "high_frequency_write": 0.30,
        "bulk_file_modify": 0.25,
        "targeted_user_file_extensions": 0.20,
        "bulk_file_create": 0.15,
        "suspicious_child_process_spawn": 0.20,
        "process_execution_observed": 0.05,
    }
    breakdown = [
        {
            "feature": feature,
            "weight": weights[feature],
            "score": 1.0,
            "reason": "Matched normalized dynamic behavior feature.",
        }
        for feature in features
        if feature in weights
    ]
    return round(min(1.0, sum(item["weight"] for item in breakdown)), 3), breakdown


def run_dynamic_analysis(context: AnalysisContext, bundle: RuntimeConfigBundle) -> AnalysisContext:
    result = context.dynamic_analysis
    result.executed = False
    result.environment = bundle.dynamic_analysis.environment_type
    result.tools_used = []
    result.adapter_selected = ""
    result.adapter_candidates = []
    result.input_artifact_path = ""
    result.artifact_schema_version = ""
    result.artifact_validation = {}
    result.behavior_summary = {}

    if not bundle.dynamic_analysis.enabled:
        result.status = ModuleStatus.SKIPPED.value
        result.execution_status = ModuleStatus.SKIPPED.value
        result.summary = "Dynamic analysis disabled by config; no sample execution performed."
        return context

    agent_request = context.agent_execution.dynamic_request
    adapter_candidates: list[str] = []
    if bundle.dynamic_analysis.allow_agent_override and agent_request.preferred_adapter:
        adapter_candidates.append(agent_request.preferred_adapter)
        adapter_candidates.extend(agent_request.fallback_adapters)
    else:
        adapter_candidates.append(bundle.dynamic_analysis.adapter_name)

    if bundle.dynamic_analysis.fallback_adapters:
        adapter_candidates.extend(bundle.dynamic_analysis.fallback_adapters)
    adapter_candidates = [name for index, name in enumerate(adapter_candidates) if name and name not in adapter_candidates[:index]]
    result.adapter_candidates = adapter_candidates
    result.input_artifact_path = agent_request.input_artifact_path or bundle.dynamic_analysis.event_log_path

    if not adapter_candidates:
        result.status = ModuleStatus.PARTIAL.value
        result.execution_status = "not_configured"
        result.summary = "Dynamic analysis enabled, but no adapter candidates are configured."
        result.error = "DYNAMIC_ENVIRONMENT_UNAVAILABLE"
        return context

    if agent_request.allow_sample_execution and not bundle.dynamic_analysis.allow_sample_execution:
        result.status = ModuleStatus.PARTIAL.value
        result.execution_status = "execution_blocked"
        result.summary = "Agent requested sample execution, but the configuration keeps host-side execution disabled."
        result.error = "DYNAMIC_EXECUTION_BLOCKED"
        return context

    try:
        adapter_output = select_dynamic_adapter_candidates(
            adapter_candidates,
            event_log_path=bundle.dynamic_analysis.event_log_path,
            replay_artifact_dir=bundle.dynamic_analysis.replay_artifact_dir,
            input_artifact_path=agent_request.input_artifact_path,
        )
    except Exception as exc:
        result.status = ModuleStatus.ERROR.value
        result.execution_status = "event_log_parse_failed"
        result.error = f"DYNAMIC_EVENT_EXPORT_FAILURE: {exc}"
        result.summary = "Failed to parse configured dynamic event log."
        return context

    if adapter_output.adapter_status != "ok":
        result.status = ModuleStatus.PARTIAL.value
        result.execution_status = adapter_output.adapter_status
        result.tools_used = [adapter_output.adapter_name]
        result.adapter_selected = adapter_output.adapter_name
        result.input_artifact_path = adapter_output.input_artifact_path or result.input_artifact_path
        result.artifact_schema_version = adapter_output.schema_version
        result.artifact_validation = adapter_output.validation or {}
        result.summary = adapter_output.summary
        result.error = "DYNAMIC_ADAPTER_UNAVAILABLE"
        return context

    process_events = adapter_output.process_events
    file_events = adapter_output.file_events

    result.executed = True
    result.status = ModuleStatus.OK.value
    result.execution_status = "success"
    result.process_events = process_events
    result.file_events = file_events
    result.tools_used = [adapter_output.adapter_name]
    result.adapter_selected = adapter_output.adapter_name
    result.input_artifact_path = adapter_output.input_artifact_path
    result.artifact_schema_version = adapter_output.schema_version
    result.artifact_validation = adapter_output.validation or {}
    result.behavior_summary = _build_behavior_summary(process_events, file_events)
    result.matched_features = _normalize_features(process_events, file_events, bundle)
    result.risk_score, result.score_breakdown = _score_dynamic_features(result.matched_features)
    result.summary = adapter_output.summary or "Dynamic event log analysis completed."
    return context
