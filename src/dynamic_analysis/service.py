from __future__ import annotations

import json
from pathlib import Path

from config.loader import RuntimeConfigBundle
from core.enums import ModuleStatus
from models.analysis_context import AnalysisContext


def _load_event_log(path: str) -> tuple[list[dict], list[dict]]:
    if not path:
        return [], []
    event_path = Path(path)
    if not event_path.exists():
        return [], []
    data = json.loads(event_path.read_text(encoding="utf-8"))
    return data.get("process_events", []), data.get("file_events", [])


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

    if not bundle.dynamic_analysis.enabled:
        result.status = ModuleStatus.SKIPPED.value
        result.execution_status = ModuleStatus.SKIPPED.value
        result.summary = "Dynamic analysis disabled by config; no sample execution performed."
        return context

    if not bundle.dynamic_analysis.event_log_path:
        result.status = ModuleStatus.PARTIAL.value
        result.execution_status = "not_configured"
        result.summary = "Dynamic analysis enabled, but no event log adapter is configured."
        result.error = "DYNAMIC_ENVIRONMENT_UNAVAILABLE"
        return context

    try:
        process_events, file_events = _load_event_log(bundle.dynamic_analysis.event_log_path)
    except Exception as exc:
        result.status = ModuleStatus.ERROR.value
        result.execution_status = "event_log_parse_failed"
        result.error = f"DYNAMIC_EVENT_EXPORT_FAILURE: {exc}"
        result.summary = "Failed to parse configured dynamic event log."
        return context

    result.executed = True
    result.status = ModuleStatus.OK.value
    result.execution_status = "success"
    result.process_events = process_events
    result.file_events = file_events
    result.tools_used = ["event_log_adapter"]
    result.matched_features = _normalize_features(process_events, file_events, bundle)
    result.risk_score, result.score_breakdown = _score_dynamic_features(result.matched_features)
    result.summary = "Dynamic event log analysis completed."
    return context

