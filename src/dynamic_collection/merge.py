from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def _aggregate_file_events(file_events: list[dict]) -> list[dict]:
    buckets: dict[str, dict] = defaultdict(
        lambda: {
            "path_hint": "",
            "created_count": 0,
            "modified_count": 0,
            "renamed_count": 0,
            "high_frequency_write": False,
            "target_extensions": [],
        }
    )
    for event in file_events:
        path_hint = str(event.get("path_hint") or "")
        bucket = buckets[path_hint]
        bucket["path_hint"] = path_hint
        bucket["created_count"] += int(event.get("created_count", 0) or 0)
        bucket["modified_count"] += int(event.get("modified_count", 0) or 0)
        bucket["renamed_count"] += int(event.get("renamed_count", 0) or 0)
        bucket["high_frequency_write"] = bucket["high_frequency_write"] or bool(event.get("high_frequency_write", False))
        bucket["target_extensions"].extend(event.get("target_extensions") or [])

    merged = []
    for bucket in buckets.values():
        bucket["target_extensions"] = sorted(set(str(value) for value in bucket["target_extensions"] if value))
        merged.append(bucket)
    return merged


def build_unified_raw_log(
    *,
    sample_sha256: str,
    sysmon_data: dict | None = None,
    procmon_data: dict | None = None,
    output_path: str,
) -> str:
    process_events: list[dict] = []
    file_events: list[dict] = []
    sources: list[str] = []

    for source_name, data in (("sysmon", sysmon_data), ("procmon", procmon_data)):
        if not data:
            continue
        sources.append(source_name)
        process_events.extend(data.get("process_events", []) or [])
        file_events.extend(data.get("file_events", []) or [])

    payload = {
        "schema_version": "dynamic-raw-log.v1",
        "sample": {"sha256": sample_sha256},
        "sources": sources,
        "process_events": process_events,
        "file_events": _aggregate_file_events(file_events),
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return str(path)
