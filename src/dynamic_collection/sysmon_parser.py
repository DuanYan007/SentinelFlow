from __future__ import annotations

import json
from pathlib import Path


def parse_sysmon_json(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("sysmon root must be an object")

    sample_sha256 = str(data.get("sample_sha256") or "").strip()
    events = data.get("events", []) or []
    process_events: list[dict] = []
    file_events: list[dict] = []

    for event in events:
        if not isinstance(event, dict):
            continue
        event_id = int(event.get("event_id", 0) or 0)
        if event_id == 1:
            process_events.append(
                {
                    "process_name": event.get("image") or event.get("process_name") or "",
                    "pid": int(event.get("pid", 0) or 0),
                    "parent_pid": int(event.get("parent_pid", 0) or 0),
                    "suspicious_spawn": bool(event.get("suspicious_spawn", False)),
                }
            )
        elif event_id in {11, 15}:
            file_events.append(
                {
                    "path_hint": event.get("target_filename") or event.get("path_hint") or "",
                    "created_count": int(event.get("created_count", 0) or 0),
                    "modified_count": int(event.get("modified_count", 0) or 0),
                    "renamed_count": int(event.get("renamed_count", 0) or 0),
                    "high_frequency_write": bool(event.get("high_frequency_write", False)),
                    "target_extensions": event.get("target_extensions") or [],
                }
            )

    return {
        "source_type": "sysmon",
        "sample_sha256": sample_sha256,
        "process_events": process_events,
        "file_events": file_events,
    }
