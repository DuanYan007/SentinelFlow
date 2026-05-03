from __future__ import annotations

import json
from pathlib import Path


def parse_procmon_json(path: str) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("procmon root must be an object")

    sample_sha256 = str(data.get("sample_sha256") or "").strip()
    rows = data.get("rows", []) or []
    process_events: list[dict] = []
    file_events: list[dict] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        operation = str(row.get("operation") or "")
        path_value = str(row.get("path") or "")
        process_name = str(row.get("process_name") or "")
        if operation in {"Process Start", "CreateProcess"}:
            process_events.append(
                {
                    "process_name": process_name,
                    "pid": int(row.get("pid", 0) or 0),
                    "parent_pid": int(row.get("parent_pid", 0) or 0),
                    "suspicious_spawn": bool(row.get("suspicious_spawn", False)),
                }
            )
        elif operation in {"CreateFile", "WriteFile", "SetRenameInformationFile"}:
            suffix = Path(path_value).suffix.lower()
            file_events.append(
                {
                    "path_hint": path_value,
                    "created_count": 1 if operation == "CreateFile" else 0,
                    "modified_count": 1 if operation == "WriteFile" else 0,
                    "renamed_count": 1 if operation == "SetRenameInformationFile" else 0,
                    "high_frequency_write": bool(row.get("high_frequency_write", False)),
                    "target_extensions": [suffix] if suffix else [],
                }
            )

    return {
        "source_type": "procmon",
        "sample_sha256": sample_sha256,
        "process_events": process_events,
        "file_events": file_events,
    }
