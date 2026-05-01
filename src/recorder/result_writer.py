import json
from dataclasses import asdict
from pathlib import Path

from models.analysis_context import AnalysisContext
from .path_resolver import resolve_result_path
from .validator import validate_analysis_context


def write_single_result(context: AnalysisContext, output_dir: str) -> str:
    validation = validate_analysis_context(context)
    if not validation.valid:
        raise ValueError(f"analysis context validation failed: {validation.errors}")

    path = resolve_result_path(context, output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(asdict(context), handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    return str(path)

