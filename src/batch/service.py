from __future__ import annotations

from collections import Counter
from pathlib import Path

from config.loader import RuntimeConfigBundle
from core.ids import generate_batch_id
from core.time_utils import duration_seconds, now_iso
from models.batch_summary import BatchSummary
from recorder.result_writer import write_single_result
from recorder.summary_writer import write_batch_summary
from workflow_skeleton import single_sample_workflow


def _load_sample_paths(input_dir: str | None = None, sample_list: list[str] | None = None) -> list[Path]:
    paths: list[Path] = []
    if input_dir:
        paths.extend(sorted(Path(input_dir).iterdir()))
    if sample_list:
        paths.extend(Path(item) for item in sample_list)
    return paths


def _deduplicate_files(paths: list[Path]) -> tuple[list[Path], int, int]:
    file_paths = [path for path in paths if path.is_file()]
    skipped_non_files = len(paths) - len(file_paths)
    seen_names: set[str] = set()
    unique: list[Path] = []
    duplicates = 0
    for path in file_paths:
        key = str(path.resolve())
        if key in seen_names:
            duplicates += 1
            continue
        seen_names.add(key)
        unique.append(path)
    return unique, skipped_non_files, duplicates


def _build_summary(
    batch_id: str,
    started_at: str,
    ended_at: str,
    result_paths: list[str],
    contexts: list,
    total_input_count: int,
    skipped_non_files: int,
    duplicate_count: int,
    bundle: RuntimeConfigBundle,
) -> BatchSummary:
    labels = Counter(context.verdict.final_label for context in contexts)
    workflow_statuses = Counter(context.workflow_status.status for context in contexts)
    static_statuses = Counter(context.static_analysis.status for context in contexts)
    vt_statuses = Counter(context.threat_intel.status for context in contexts)

    completed = workflow_statuses.get("completed", 0) + workflow_statuses.get("completed_degraded", 0)
    failed = workflow_statuses.get("failed_early", 0)
    duration_values = [context.runtime.duration_sec for context in contexts if context.runtime.duration_sec is not None]

    return BatchSummary(
        batch_id=batch_id,
        runtime={
            "start_time": started_at,
            "end_time": ended_at,
            "duration_sec": duration_seconds(started_at, ended_at),
            "phase": bundle.phase1.phase_name,
        },
        input_stats={
            "total_inputs": total_input_count,
            "processed_samples": len(contexts),
            "skipped_non_files": skipped_non_files,
            "duplicate_skipped_count": duplicate_count,
        },
        workflow_stats={
            "successful_count": completed,
            "partial_count": workflow_statuses.get("completed_degraded", 0),
            "failed_count": failed,
            "rerun_count": sum(context.runtime.rerun_count for context in contexts),
            "avg_duration_sec": round(sum(duration_values) / len(duration_values), 3) if duration_values else 0.0,
        },
        label_stats=dict(labels),
        module_stats={
            "vt": dict(vt_statuses),
            "static": dict(static_statuses),
        },
        failure_stats={
            "workflow_statuses": dict(workflow_statuses),
        },
        artifacts={
            "result_paths": result_paths,
            "summary_version": "phase1-batch-v1",
        },
        phase=bundle.phase1.phase_name,
    )


def run_batch(
    bundle: RuntimeConfigBundle,
    input_dir: str | None = None,
    sample_list: list[str] | None = None,
    max_samples: int | None = None,
) -> BatchSummary:
    batch_id = generate_batch_id()
    started_at = now_iso()
    raw_paths = _load_sample_paths(input_dir=input_dir, sample_list=sample_list)
    unique_paths, skipped_non_files, duplicate_count = _deduplicate_files(raw_paths)
    if max_samples is not None:
        unique_paths = unique_paths[:max_samples]

    contexts = []
    result_paths: list[str] = []
    for sample_path in unique_paths:
        context = single_sample_workflow(str(sample_path), bundle)
        context.runtime.batch_id = batch_id
        result_paths.append(write_single_result(context, bundle.phase1.results_dir))
        contexts.append(context)

    ended_at = now_iso()
    summary = _build_summary(
        batch_id=batch_id,
        started_at=started_at,
        ended_at=ended_at,
        result_paths=result_paths,
        contexts=contexts,
        total_input_count=len(raw_paths),
        skipped_non_files=skipped_non_files,
        duplicate_count=duplicate_count,
        bundle=bundle,
    )
    write_batch_summary(summary, f"{bundle.phase1.results_dir}/summaries")
    return summary
