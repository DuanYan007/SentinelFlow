from pathlib import Path


def build_result_filename(workflow_id: str, sha256_prefix: str, mode: str) -> str:
    sample_hint = sha256_prefix or "unhashed"
    return f"{workflow_id}__{sample_hint}__{mode}.json"


def build_summary_filename(batch_id: str) -> str:
    return f"{batch_id}__summary.json"


def resolve_result_path(output_dir: str | Path, workflow_id: str, sha256_prefix: str, mode: str) -> Path:
    base = Path(output_dir)
    return base / build_result_filename(workflow_id, sha256_prefix, mode)


def resolve_summary_path(output_dir: str | Path, batch_id: str) -> Path:
    base = Path(output_dir)
    return base / build_summary_filename(batch_id)

