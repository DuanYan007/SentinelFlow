from core.enums import ModuleStatus, WorkflowStage
from core.time_utils import now_iso
from models.agent_trace_item import AgentTraceItem
from models.analysis_context import AnalysisContext


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


def run_agent_decision(context: AnalysisContext, stage: str) -> AnalysisContext:
    if stage == WorkflowStage.HASH_INTEL.value:
        input_summary = {
            "vt_status": context.threat_intel.status,
            "vt_signal": context.threat_intel.vt_signal,
            "matched": context.threat_intel.matched,
        }
        _append_trace(
            context,
            stage="agent_decision_1",
            decision="continue_to_static",
            reason="Phase 1 requires static evidence collection after threat-intelligence handling.",
            input_summary=input_summary,
        )
        return context

    if stage == WorkflowStage.STATIC_ANALYSIS.value:
        v2_data = context.static_analysis.v2 if isinstance(context.static_analysis.v2, dict) else {}
        v2_risk_score = v2_data.get("risk_score")
        v2_categories = sorted(
            (v2_data.get("normalized_features", {}).get("import_features", {}).get("categories", {}) or {}).keys()
        )
        if isinstance(v2_risk_score, (int, float)):
            if v2_risk_score >= 0.60:
                next_action = "prioritize_dynamic_analysis"
                next_reason = "Static-analysis v2 shows high structured risk and should drive stronger follow-up."
            elif v2_risk_score >= 0.30:
                next_action = "collect_more_static_and_dynamic_evidence"
                next_reason = "Static-analysis v2 shows medium structured risk and suggests broader evidence collection."
            else:
                next_action = "keep_minimum_dynamic_path"
                next_reason = "Static-analysis v2 remains low-risk and can continue through the minimum dynamic path."
        else:
            next_action = "v2_unavailable"
            next_reason = "Static-analysis v2 output is unavailable, so the agent falls back to the v1-compatible path."

        input_summary = {
            "static_status": context.static_analysis.status,
            "static_risk_score": context.static_analysis.risk_score,
            "matched_features": context.static_analysis.matched_features,
            "static_v2_risk_score": v2_risk_score,
            "static_v2_import_categories": v2_categories,
            "suggested_next_action": next_action,
        }
        _append_trace(
            context,
            stage="agent_decision_2",
            decision="continue_to_final_verdict",
            reason=(
                "Static evidence has been collected and the current round ends at verdict generation before dynamic integration. "
                f"V2 experimental suggestion: {next_reason}"
            ),
            input_summary=input_summary,
            confidence=0.75,
        )
        return context

    if stage == WorkflowStage.FINAL_VERDICT.value:
        input_summary = {
            "static_status": context.static_analysis.status,
            "dynamic_status": context.dynamic_analysis.status,
            "workflow_status": context.workflow_status.status,
            "verdict_label": context.verdict.final_label,
        }
        _append_trace(
            context,
            stage="final_verdict",
            decision="produce_final_verdict",
            reason="The workflow has enough normalized evidence for the current implementation round to emit a verdict.",
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
