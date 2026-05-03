from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from config.loader import RuntimeConfigBundle
from core.ids import generate_batch_id
from core.time_utils import duration_seconds, now_iso
from dynamic_analysis import run_dynamic_analysis
from ingest import run_ingest
from models.analysis_context import create_empty_analysis_context


def _load_artifact_paths(input_dir: str) -> tuple[list[Path], int]:
    raw_paths = sorted(Path(input_dir).iterdir())
    file_paths = [path for path in raw_paths if path.is_file() and path.name.endswith(".dynamic.json")]
    skipped = len(raw_paths) - len(file_paths)
    return file_paths, skipped


def _write_dynamic_result(output_dir: Path, batch_id: str, context) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_sha = context.sample.sha256[:12] if context.sample.sha256 else context.sample.file_name
    path = output_dir / f"{batch_id}__{sample_sha}__dynamic.json"
    payload = {
        "sample": context.sample.__dict__,
        "agent_execution": asdict(context.agent_execution),
        "dynamic_analysis": asdict(context.dynamic_analysis),
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


def run_dynamic_experiment(
    bundle: RuntimeConfigBundle,
    input_dir: str,
    output_dir: str,
) -> dict:
    batch_id = f"dynamic-{generate_batch_id()}"
    started_at = now_iso()
    artifact_paths, skipped_non_files = _load_artifact_paths(input_dir)
    result_dir = Path(output_dir) / batch_id

    result_paths: list[str] = []
    contexts = []
    for artifact_path in artifact_paths:
        sample_name = artifact_path.name.removesuffix(".dynamic.json")
        context = create_empty_analysis_context(str(artifact_path), bundle.phase1.phase_name)
        context = run_ingest(context)
        if not context.workflow_status.fatal:
            context.sample.sha256 = sample_name if len(sample_name) == 64 else context.sample.sha256
            context.agent_execution.dynamic_request.input_artifact_path = artifact_path.name
            context.agent_execution.dynamic_request.preferred_adapter = "sample_replay_adapter"
            context.agent_execution.dynamic_request.fallback_adapters = ["event_log_adapter"]
            context = run_dynamic_analysis(context, bundle)
        context.runtime.end_time = now_iso()
        context.runtime.duration_sec = duration_seconds(context.runtime.start_time, context.runtime.end_time)
        result_paths.append(_write_dynamic_result(result_dir, batch_id, context))
        contexts.append(context)

    ended_at = now_iso()
    dynamic_statuses = Counter(context.dynamic_analysis.status for context in contexts)
    selected_adapters = Counter(context.dynamic_analysis.adapter_selected or "none" for context in contexts)
    risk_scores = [context.dynamic_analysis.risk_score for context in contexts]
    mean_risk_score = round(sum(risk_scores) / len(risk_scores), 3) if risk_scores else 0.0

    summary = {
        "batch_id": batch_id,
        "runtime": {
            "start_time": started_at,
            "end_time": ended_at,
            "duration_sec": duration_seconds(started_at, ended_at),
            "phase": bundle.phase1.phase_name,
            "experiment_type": "dynamic_only",
        },
        "input_stats": {
            "input_dir": input_dir,
            "total_entries": len(artifact_paths) + skipped_non_files,
            "processed_artifacts": len(artifact_paths),
            "skipped_non_files": skipped_non_files,
        },
        "dynamic_stats": {
            "status_counts": dict(dynamic_statuses),
            "adapter_counts": dict(selected_adapters),
            "mean_risk_score": mean_risk_score,
        },
        "artifacts": {
            "result_dir": str(result_dir),
            "result_paths": result_paths[:20],
            "result_count": len(result_paths),
        },
    }

    summary_dir = Path(output_dir) / "summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_file = summary_dir / f"{batch_id}__summary.json"
    with summary_file.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=True, indent=2)
        handle.write("\n")

    return summary
