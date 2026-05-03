from pathlib import Path

from agent import run_agent_decision
from core.constants import DEFAULT_CONFIGS_DIR
from core.enums import FinalLabel, ModuleStatus, WorkflowStage, WorkflowState
from core.time_utils import duration_seconds, now_iso
from config.loader import RuntimeConfigBundle, load_runtime_config
from dynamic_collection import prepare_real_dynamic_artifacts
from ingest import run_ingest
from intel import run_threat_intel
from models.analysis_context import AnalysisContext, create_empty_analysis_context
from dynamic_analysis import run_dynamic_analysis
from recorder.result_writer import write_single_result
from static_analysis import run_static_analysis
from verdict import run_verdict


def initialize_context(sample_path: str, phase_name: str) -> AnalysisContext:
    return create_empty_analysis_context(sample_path=sample_path, phase_name=phase_name)


def finalize_context(context: AnalysisContext) -> AnalysisContext:
    context.runtime.end_time = now_iso()
    context.runtime.duration_sec = duration_seconds(context.runtime.start_time, context.runtime.end_time)
    if not context.verdict.decision_basis:
        context.verdict.decision_basis = ["round-3 placeholder workflow"]
    if not context.verdict.explanation:
        context.verdict.explanation = "Round-3 skeleton output with ingest, optional VT, static analysis, and verdict generation."
    if not context.verdict.final_label:
        context.verdict.final_label = FinalLabel.SUSPICIOUS.value
    if context.workflow_status.status == WorkflowState.INITIALIZED.value:
        context.workflow_status.status = WorkflowState.COMPLETED_DEGRADED.value
        context.workflow_status.message = "Round-3 workflow completed."
    return context


def single_sample_workflow(sample_path: str, runtime_config: RuntimeConfigBundle) -> AnalysisContext:
    context = initialize_context(sample_path=sample_path, phase_name=runtime_config.phase1.phase_name)
    context = run_ingest(context)
    if context.workflow_status.fatal:
        return finalize_context(context)

    context = run_threat_intel(context, runtime_config)
    context = run_agent_decision(context, WorkflowStage.HASH_INTEL.value)

    context = run_static_analysis(context, runtime_config)
    context = run_agent_decision(context, WorkflowStage.STATIC_ANALYSIS.value)

    if runtime_config.dynamic_analysis.real_runs_dir:
        real_dynamic_prep = prepare_real_dynamic_artifacts(context, runtime_config)
        context.runtime.notes = (
            f"{context.runtime.notes}; {real_dynamic_prep.summary}".strip("; ").strip()
            if real_dynamic_prep.summary
            else context.runtime.notes
        )

    context = run_dynamic_analysis(context, runtime_config)
    context = run_agent_decision(context, WorkflowStage.DYNAMIC_ANALYSIS.value)

    context = run_verdict(context, runtime_config)
    context = run_agent_decision(context, WorkflowStage.FINAL_VERDICT.value)
    return finalize_context(context)


def run_round1_placeholder(sample_path: str, config_dir: str = DEFAULT_CONFIGS_DIR) -> str:
    runtime_config = load_runtime_config(config_dir)
    context = single_sample_workflow(sample_path, runtime_config)
    return write_single_result(context, runtime_config.phase1.results_dir)
