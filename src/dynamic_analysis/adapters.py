from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DynamicAdapterOutput:
    process_events: list[dict]
    file_events: list[dict]
    adapter_name: str
    adapter_status: str
    summary: str = ""
    input_artifact_path: str = ""
    schema_version: str = ""
    validation: dict | None = None


def _load_json_artifact(path: Path, adapter_name: str, summary: str) -> DynamicAdapterOutput:
    data = json.loads(path.read_text(encoding="utf-8"))
    process_events = data.get("process_events", [])
    file_events = data.get("file_events", [])
    validation = validate_dynamic_artifact_data(data)
    return DynamicAdapterOutput(
        process_events=process_events if validation["valid"] else [],
        file_events=file_events if validation["valid"] else [],
        adapter_name=adapter_name,
        adapter_status="ok" if validation["valid"] else "invalid_artifact",
        summary=summary if validation["valid"] else "Dynamic artifact schema validation failed.",
        input_artifact_path=str(path),
        schema_version=str(data.get("schema_version", "")),
        validation=validation,
    )


def validate_dynamic_artifact_data(data: dict) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, dict):
        return {"valid": False, "errors": ["artifact root must be an object"], "warnings": warnings}

    process_events = data.get("process_events", [])
    file_events = data.get("file_events", [])
    if not isinstance(process_events, list):
        errors.append("process_events must be a list")
    if not isinstance(file_events, list):
        errors.append("file_events must be a list")
    if isinstance(process_events, list):
        for index, item in enumerate(process_events):
            if not isinstance(item, dict):
                errors.append(f"process_events[{index}] must be an object")
    if isinstance(file_events, list):
        for index, item in enumerate(file_events):
            if not isinstance(item, dict):
                errors.append(f"file_events[{index}] must be an object")
    if not data.get("schema_version"):
        warnings.append("schema_version is missing; treating artifact as legacy format")
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def load_event_log_adapter(event_log_path: str) -> DynamicAdapterOutput:
    if not event_log_path:
        return DynamicAdapterOutput(
            process_events=[],
            file_events=[],
            adapter_name="event_log_adapter",
            adapter_status="not_configured",
            summary="No event log path configured.",
        )

    path = Path(event_log_path)
    if not path.exists():
        return DynamicAdapterOutput(
            process_events=[],
            file_events=[],
            adapter_name="event_log_adapter",
            adapter_status="missing_input",
            summary=f"Configured event log path does not exist: {path}",
        )

    return _load_json_artifact(
        path,
        adapter_name="event_log_adapter",
        summary="Dynamic event log loaded from configured JSON artifact.",
    )


def load_sample_replay_adapter(replay_artifact_dir: str, input_artifact_path: str) -> DynamicAdapterOutput:
    if not replay_artifact_dir:
        return DynamicAdapterOutput(
            process_events=[],
            file_events=[],
            adapter_name="sample_replay_adapter",
            adapter_status="not_configured",
            summary="No replay artifact directory configured.",
        )
    if not input_artifact_path:
        return DynamicAdapterOutput(
            process_events=[],
            file_events=[],
            adapter_name="sample_replay_adapter",
            adapter_status="missing_input",
            summary="Agent did not provide a replay artifact path for the sample.",
        )

    candidate = Path(replay_artifact_dir) / input_artifact_path
    if not candidate.exists():
        return DynamicAdapterOutput(
            process_events=[],
            file_events=[],
            adapter_name="sample_replay_adapter",
            adapter_status="missing_input",
            summary=f"Replay artifact does not exist: {candidate}",
            input_artifact_path=str(candidate),
        )

    return _load_json_artifact(
        candidate,
        adapter_name="sample_replay_adapter",
        summary="Dynamic replay artifact loaded from sample-specific JSON input.",
    )


def load_dynamic_adapter(
    adapter_name: str,
    *,
    event_log_path: str,
    replay_artifact_dir: str,
    input_artifact_path: str,
) -> DynamicAdapterOutput:
    if adapter_name == "event_log_adapter":
        return load_event_log_adapter(event_log_path)
    if adapter_name == "sample_replay_adapter":
        return load_sample_replay_adapter(replay_artifact_dir, input_artifact_path)
    return DynamicAdapterOutput(
        process_events=[],
        file_events=[],
        adapter_name=adapter_name or "unknown",
        adapter_status="unsupported_adapter",
        summary=f"Unsupported dynamic adapter: {adapter_name}",
    )


def select_dynamic_adapter_candidates(
    adapter_candidates: list[str],
    *,
    event_log_path: str,
    replay_artifact_dir: str,
    input_artifact_path: str,
) -> DynamicAdapterOutput:
    for adapter_name in adapter_candidates:
        output = load_dynamic_adapter(
            adapter_name,
            event_log_path=event_log_path,
            replay_artifact_dir=replay_artifact_dir,
            input_artifact_path=input_artifact_path,
        )
        if output.adapter_status == "ok":
            return output
        if output.adapter_status == "unsupported_adapter":
            continue
        last_output = output
    return last_output if "last_output" in locals() else DynamicAdapterOutput(
        process_events=[],
        file_events=[],
        adapter_name="unknown",
        adapter_status="unsupported_adapter",
        summary="No dynamic adapter candidates were provided.",
    )
