from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from config.loader import RuntimeConfigBundle
from core.ids import generate_batch_id
from core.time_utils import duration_seconds, now_iso
from ingest import run_ingest
from models.analysis_context import create_empty_analysis_context
from recorder.summary_writer import write_batch_summary
from static_analysis import run_static_analysis


def _load_file_paths(input_dir: str) -> tuple[list[Path], int]:
    raw_paths = sorted(Path(input_dir).iterdir())
    file_paths = [path for path in raw_paths if path.is_file()]
    skipped = len(raw_paths) - len(file_paths)
    return file_paths, skipped


def _write_static_result(output_dir: Path, batch_id: str, context) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_sha = context.sample.sha256[:12] if context.sample.sha256 else context.sample.file_name
    path = output_dir / f"{batch_id}__{sample_sha}__static.json"
    payload = {
        "sample": context.sample.__dict__,
        "static_analysis": context.static_analysis.__dict__,
        "runtime": {
            "workflow_id": context.runtime.workflow_id,
            "start_time": context.runtime.start_time,
            "end_time": context.runtime.end_time,
            "duration_sec": context.runtime.duration_sec,
            "phase": context.runtime.phase,
        },
        "workflow_status": context.workflow_status.__dict__,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    return str(path)


def run_static_experiment(
    bundle: RuntimeConfigBundle,
    input_dir: str,
    output_dir: str,
) -> dict:
    batch_id = f"static-{generate_batch_id()}"
    started_at = now_iso()
    sample_paths, skipped_non_files = _load_file_paths(input_dir)
    result_dir = Path(output_dir) / batch_id

    result_paths: list[str] = []
    contexts = []
    for sample_path in sample_paths:
        context = create_empty_analysis_context(str(sample_path), bundle.phase1.phase_name)
        context = run_ingest(context)
        if not context.workflow_status.fatal:
            context = run_static_analysis(context, bundle)
        context.runtime.end_time = now_iso()
        context.runtime.duration_sec = duration_seconds(context.runtime.start_time, context.runtime.end_time)
        result_paths.append(_write_static_result(result_dir, batch_id, context))
        contexts.append(context)

    ended_at = now_iso()
    static_statuses = Counter(context.static_analysis.status for context in contexts)
    v2_present_count = sum(1 for context in contexts if context.static_analysis.v2)
    v2_risk_scores = [
        context.static_analysis.v2.get("risk_score")
        for context in contexts
        if isinstance(context.static_analysis.v2, dict) and isinstance(context.static_analysis.v2.get("risk_score"), (int, float))
    ]
    mean_v2_score = round(sum(v2_risk_scores) / len(v2_risk_scores), 3) if v2_risk_scores else 0.0

    summary = {
        "batch_id": batch_id,
        "runtime": {
            "start_time": started_at,
            "end_time": ended_at,
            "duration_sec": duration_seconds(started_at, ended_at),
            "phase": bundle.phase1.phase_name,
            "experiment_type": "static_only",
        },
        "input_stats": {
            "input_dir": input_dir,
            "total_entries": len(sample_paths) + skipped_non_files,
            "processed_samples": len(sample_paths),
            "skipped_non_files": skipped_non_files,
        },
        "static_stats": {
            "status_counts": dict(static_statuses),
            "v2_present_count": v2_present_count,
            "v2_mean_risk_score": mean_v2_score,
        },
        "artifacts": {
            "result_dir": str(result_dir),
            "result_paths": result_paths[:20],
            "result_count": len(result_paths),
        },
    }

    summary_path = Path(output_dir) / "summaries"
    summary_path.mkdir(parents=True, exist_ok=True)
    summary_file = summary_path / f"{batch_id}__summary.json"
    with summary_file.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=True, indent=2)
        handle.write("\n")

    return summary
