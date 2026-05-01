from hashlib import md5, sha1, sha256
from pathlib import Path

from core.enums import WorkflowState
from models.analysis_context import AnalysisContext


def _detect_file_type(sample_path: Path) -> str:
    try:
        with sample_path.open("rb") as handle:
            header = handle.read(2)
    except OSError:
        return "unknown"
    if header == b"MZ":
        return "PE"
    return "unknown"


def _compute_hashes(sample_path: Path) -> tuple[str, str, str]:
    md5_hash = md5()
    sha1_hash = sha1()
    sha256_hash = sha256()
    with sample_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()


def run_ingest(context: AnalysisContext) -> AnalysisContext:
    sample_path = Path(context.sample.file_path)
    context.sample.file_name = sample_path.name

    if not sample_path.exists():
        context.workflow_status.status = WorkflowState.FAILED_EARLY.value
        context.workflow_status.fatal = True
        context.workflow_status.error_code = "INPUT_FILE_NOT_FOUND"
        context.workflow_status.message = f"Sample does not exist: {sample_path}"
        return context

    if not sample_path.is_file():
        context.workflow_status.status = WorkflowState.FAILED_EARLY.value
        context.workflow_status.fatal = True
        context.workflow_status.error_code = "INPUT_UNSUPPORTED_TYPE"
        context.workflow_status.message = f"Sample path is not a file: {sample_path}"
        return context

    context.sample.file_size = sample_path.stat().st_size
    context.sample.file_type = _detect_file_type(sample_path)

    try:
        context.sample.md5, context.sample.sha1, context.sample.sha256 = _compute_hashes(sample_path)
    except OSError as exc:
        context.workflow_status.status = WorkflowState.FAILED_EARLY.value
        context.workflow_status.fatal = True
        context.workflow_status.error_code = "INPUT_FILE_UNREADABLE"
        context.workflow_status.message = str(exc)
        return context

    return context
