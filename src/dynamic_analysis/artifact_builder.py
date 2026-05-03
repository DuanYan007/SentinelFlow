from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DynamicArtifactBuildResult:
    schema_version: str
    sample_sha256: str
    output_path: str
    process_event_count: int
    file_event_count: int
    warnings: list[str]


def _normalize_process_events(events: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        normalized.append(
            {
                "image": event.get("image") or event.get("process_name") or "",
                "pid": int(event.get("pid", 0) or 0),
                "parent_pid": int(event.get("parent_pid", 0) or 0),
                "suspicious_spawn": bool(event.get("suspicious_spawn", False)),
            }
        )
    return normalized


def _normalize_file_events(events: list[dict]) -> list[dict]:
    normalized: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        target_extensions = event.get("target_extensions") or []
        if not isinstance(target_extensions, list):
            target_extensions = []
        normalized.append(
            {
                "directory": event.get("directory") or event.get("path_hint") or "",
                "created_count": int(event.get("created_count", 0) or 0),
                "modified_count": int(event.get("modified_count", 0) or 0),
                "renamed_count": int(event.get("renamed_count", 0) or 0),
                "high_frequency_write": bool(event.get("high_frequency_write", False)),
                "target_extensions": [str(value) for value in target_extensions if value],
            }
        )
    return normalized


def _load_raw_dynamic_log(path: Path) -> tuple[str, list[dict], list[dict], list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    warnings: list[str] = []
    if not isinstance(data, dict):
        raise ValueError("raw dynamic log root must be an object")

    sample = data.get("sample", {}) or {}
    sample_sha256 = str(sample.get("sha256") or data.get("sample_sha256") or "").strip()
    if not sample_sha256:
        warnings.append("sample sha256 missing in raw log; output filename will use raw source stem")

    process_events = _normalize_process_events(data.get("process_events", []) or [])
    file_events = _normalize_file_events(data.get("file_events", []) or [])
    if not process_events and not file_events:
        warnings.append("raw log produced no normalized process_events or file_events")
    return sample_sha256, process_events, file_events, warnings


def build_dynamic_replay_artifact(raw_log_path: str, output_dir: str) -> DynamicArtifactBuildResult:
    source_path = Path(raw_log_path)
    sample_sha256, process_events, file_events, warnings = _load_raw_dynamic_log(source_path)
    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    output_name = f"{sample_sha256 or source_path.stem}.dynamic.json"
    output_path = output_root / output_name
    payload = {
        "schema_version": "dynamic-replay.v1",
        "source_format": "dynamic-raw-log.v1",
        "source_path": str(source_path),
        "sample_sha256": sample_sha256,
        "process_events": process_events,
        "file_events": file_events,
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return DynamicArtifactBuildResult(
        schema_version="dynamic-replay.v1",
        sample_sha256=sample_sha256,
        output_path=str(output_path),
        process_event_count=len(process_events),
        file_event_count=len(file_events),
        warnings=warnings,
    )
