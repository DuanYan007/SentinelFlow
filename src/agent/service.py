from core.enums import ModuleStatus, WorkflowStage
from core.time_utils import now_iso
from models.agent_trace_item import AgentTraceItem
from models.analysis_context import AnalysisContext
from .planner import build_agent_plan


def _append_trace(
    context: AnalysisContext,
    stage: str,
    decision: str,
    reason: str,
    input_summary: dict,
    confidence: float = 0.8,
    used_tool: str = "rule_based_agent",
) -> None:
    item = AgentTraceItem(
        step_id=len(context.agent_trace) + 1,
        stage=stage,
        decision=decision,
        reason=reason,
        input_summary=input_summary,
        used_skill="project-memory",
        used_tool=used_tool,
        confidence=confidence,
        timestamp=now_iso(),
    )
    context.agent_trace.append(item)


def _materialize_plan(context: AnalysisContext, stage: str) -> tuple[AnalysisContext, object]:
    plan = build_agent_plan(context, stage)
    context.agent_execution.current_strategy = plan.strategy_name
    context.agent_execution.active_stage = stage
    context.agent_execution.stage_plans[stage] = {
        "stage": plan.stage,
        "objective": plan.objective,
        "strategy_name": plan.strategy_name,
        "selected_skills": plan.selected_skills,
        "selected_tools": plan.selected_tools,
        "selected_sop_id": plan.selected_sop_id,
        "candidate_sop_ids": plan.candidate_sop_ids,
        "suggested_next_action": plan.suggested_next_action,
        "rationale": plan.rationale,
        "llm_ready_prompt_input": plan.llm_ready_prompt_input,
        "execution_directives": dict(plan.execution_directives),
    }
    return context, plan


def run_agent_decision(context: AnalysisContext, stage: str) -> AnalysisContext:
    if stage == WorkflowStage.HASH_INTEL.value:
        context, plan = _materialize_plan(context, stage)
        input_summary = {
            "vt_status": context.threat_intel.status,
            "vt_signal": context.threat_intel.vt_signal,
            "matched": context.threat_intel.matched,
            "agent_objective": plan.objective,
            "strategy_name": plan.strategy_name,
            "selected_sop_id": plan.selected_sop_id,
            "candidate_sop_ids": plan.candidate_sop_ids,
            "selected_skills": plan.selected_skills,
            "selected_tools": plan.selected_tools,
        }
        _append_trace(
            context,
            stage="agent_decision_1",
            decision=plan.suggested_next_action,
            reason=plan.rationale,
            input_summary=input_summary,
        )
        return context

    if stage == WorkflowStage.STATIC_ANALYSIS.value:
        context, plan = _materialize_plan(context, stage)
        v2_data = context.static_analysis.v2 if isinstance(context.static_analysis.v2, dict) else {}
        v2_risk_score = v2_data.get("risk_score")
        v2_categories = sorted(
            (v2_data.get("normalized_features", {}).get("import_features", {}).get("categories", {}) or {}).keys()
        )
        if isinstance(v2_risk_score, (int, float)):
            if v2_risk_score >= 0.60:
                next_action = "continue_to_verdict"
                next_reason = "Static-analysis v2 shows high structured risk and should directly influence the verdict."
            elif v2_risk_score >= 0.30:
                next_action = "continue_to_verdict"
                next_reason = "Static-analysis v2 shows medium structured risk and should directly influence the verdict."
            else:
                next_action = "continue_to_verdict"
                next_reason = "Static-analysis v2 remains low-risk and the active workflow still moves directly to verdict."
        else:
            next_action = "v2_unavailable"
            next_reason = "Static-analysis v2 output is unavailable, so the agent falls back to the static-only path."

        input_summary = {
            "static_status": context.static_analysis.status,
            "static_risk_score": context.static_analysis.risk_score,
            "matched_features": context.static_analysis.matched_features,
            "static_v2_risk_score": v2_risk_score,
            "static_v2_import_categories": v2_categories,
            "suggested_next_action": next_action,
            "agent_objective": plan.objective,
            "strategy_name": plan.strategy_name,
            "selected_sop_id": plan.selected_sop_id,
            "candidate_sop_ids": plan.candidate_sop_ids,
            "selected_skills": plan.selected_skills,
            "selected_tools": plan.selected_tools,
        }
        _append_trace(
            context,
            stage="agent_decision_2",
            decision=plan.suggested_next_action,
            reason=(
                f"{plan.rationale} V2 experimental suggestion: {next_reason}"
            ),
            input_summary=input_summary,
            confidence=0.75,
        )
        return context

    if stage == WorkflowStage.FINAL_VERDICT.value:
        context, plan = _materialize_plan(context, stage)
        input_summary = {
            "static_status": context.static_analysis.status,
            "workflow_status": context.workflow_status.status,
            "verdict_label": context.verdict.final_label,
            "strategy_name": plan.strategy_name,
            "selected_sop_id": plan.selected_sop_id,
        }
        _append_trace(
            context,
            stage="final_verdict",
            decision=plan.suggested_next_action,
            reason=plan.rationale,
            input_summary=input_summary,
            confidence=0.6,
        )
        return context

    _append_trace(
        context,
        stage=stage,
        decision="no_op",
        reason="No agent policy is defined for this stage yet.",
        input_summary={},
        confidence=0.3,
    )
    return context
