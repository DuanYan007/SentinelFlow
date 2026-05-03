from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from config.loader import RuntimeConfigBundle
from dynamic_analysis.artifact_builder import build_dynamic_replay_artifact
from models.analysis_context import AnalysisContext
from .merge import build_unified_raw_log
from .procmon_parser import parse_procmon_json
from .sysmon_parser import parse_sysmon_json


@dataclass
class RealDynamicPreparationResult:
    status: str
    summary: str
    raw_log_path: str = ""
    replay_artifact_path: str = ""


def prepare_real_dynamic_artifacts(context: AnalysisContext, bundle: RuntimeConfigBundle) -> RealDynamicPreparationResult:
    sample_sha256 = context.sample.sha256
    if not sample_sha256:
        return RealDynamicPreparationResult(
            status="skipped",
            summary="Sample sha256 is unavailable; cannot resolve real dynamic run artifacts.",
        )

    run_dir = Path(bundle.dynamic_analysis.real_runs_dir) / sample_sha256
    sysmon_path = run_dir / "sysmon.json"
    procmon_path = run_dir / "procmon.json"

    if not sysmon_path.exists() or not procmon_path.exists():
        return RealDynamicPreparationResult(
            status="missing_input",
            summary="Real dynamic run directory does not contain both sysmon.json and procmon.json.",
        )

    sysmon_data = parse_sysmon_json(str(sysmon_path))
    procmon_data = parse_procmon_json(str(procmon_path))
    raw_dir = Path(bundle.dynamic_analysis.real_runs_dir) / "raw"
    raw_path = raw_dir / f"{sample_sha256}.merged.raw.json"
    build_unified_raw_log(
        sample_sha256=sample_sha256,
        sysmon_data=sysmon_data,
        procmon_data=procmon_data,
        output_path=str(raw_path),
    )

    artifact_result = build_dynamic_replay_artifact(str(raw_path), bundle.dynamic_analysis.replay_artifact_dir)
    artifact_path = Path(artifact_result.output_path)
    context.agent_execution.dynamic_request.input_artifact_path = artifact_path.name
    context.agent_execution.dynamic_request.preferred_adapter = "sample_replay_adapter"
    context.agent_execution.dynamic_request.fallback_adapters = ["event_log_adapter"]

    return RealDynamicPreparationResult(
        status="ok",
        summary="Prepared replay artifact from real dynamic run logs.",
        raw_log_path=str(raw_path),
        replay_artifact_path=str(artifact_path),
    )
