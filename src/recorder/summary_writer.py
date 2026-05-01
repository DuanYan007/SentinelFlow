import json
from dataclasses import asdict
from pathlib import Path

from models.batch_summary import BatchSummary
from .path_resolver import resolve_summary_path


def write_batch_summary(summary: BatchSummary, output_dir: str) -> str:
    path = resolve_summary_path(summary.batch_id, output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(asdict(summary), handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    return str(path)

