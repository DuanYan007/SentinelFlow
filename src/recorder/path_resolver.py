from pathlib import Path

from core.paths import build_result_filename, build_summary_filename
from models.analysis_context import AnalysisContext


def _sample_hint(context: AnalysisContext) -> str:
    return (context.sample.sha256 or "")[:12] or "unhashed"


def resolve_result_path(context: AnalysisContext, output_dir: str) -> Path:
    return Path(output_dir) / build_result_filename(context.runtime.workflow_id, _sample_hint(context), "single")


def resolve_log_path(context: AnalysisContext, log_dir: str) -> Path:
    sample_hint = _sample_hint(context)
    return Path(log_dir) / f"{context.runtime.workflow_id}__{sample_hint}__workflow.log"


def resolve_summary_path(batch_id: str, output_dir: str) -> Path:
    return Path(output_dir) / build_summary_filename(batch_id)

