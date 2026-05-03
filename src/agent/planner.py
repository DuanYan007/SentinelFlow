from __future__ import annotations

from dataclasses import dataclass, field

from core.enums import WorkflowStage
from models.analysis_context import AnalysisContext
from models.agent_execution import AgentDynamicRequest
from .registry import AgentSOPDefinition, get_sops_for_stage


@dataclass
class AgentPlan:
    stage: str
    objective: str
    strategy_name: str = ""
    selected_skills: list[str] = field(default_factory=list)
    selected_tools: list[str] = field(default_factory=list)
    suggested_next_action: str = ""
    rationale: str = ""
    execution_directives: dict = field(default_factory=dict)
    selected_sop_id: str = ""
    candidate_sop_ids: list[str] = field(default_factory=list)
    llm_ready_prompt_input: dict = field(default_factory=dict)


def _build_dynamic_request(context: AnalysisContext) -> AgentDynamicRequest:
    sample_hash = context.sample.sha256
    replay_name = f"{sample_hash}.dynamic.json" if sample_hash else ""
    return AgentDynamicRequest(
        execution_mode="safe_replay",
        allow_sample_execution=False,
        preferred_adapter="sample_replay_adapter",
        fallback_adapters=["event_log_adapter"],
        input_artifact_path=replay_name,
        continue_on_unavailable=True,
    )


def _build_llm_ready_prompt_input(context: AnalysisContext, stage: str, candidate_sops: list[AgentSOPDefinition]) -> dict:
    v2 = context.static_analysis.v2 if isinstance(context.static_analysis.v2, dict) else {}
    return {
        "stage": stage,
        "sample": {
            "sha256": context.sample.sha256,
            "file_name": context.sample.file_name,
            "file_size": context.sample.file_size,
        },
        "threat_intel": {
            "status": context.threat_intel.status,
            "vt_signal": context.threat_intel.vt_signal,
            "matched": context.threat_intel.matched,
            "malicious_count": context.threat_intel.malicious_count,
        },
        "static_analysis": {
            "status": context.static_analysis.status,
            "risk_score": context.static_analysis.risk_score,
            "matched_features": context.static_analysis.matched_features,
            "v2_risk_score": v2.get("risk_score"),
        },
        "dynamic_analysis": {
            "status": context.dynamic_analysis.status,
            "risk_score": context.dynamic_analysis.risk_score,
            "matched_features": context.dynamic_analysis.matched_features,
        },
        "candidate_sops": [
            {
                "sop_id": sop.sop_id,
                "description": sop.description,
                "selected_skills": sop.selected_skills,
                "selected_tools": sop.selected_tools,
                "suggested_next_action": sop.suggested_next_action,
            }
            for sop in candidate_sops
        ],
    }


def _plan_from_sop(
    context: AnalysisContext,
    sop: AgentSOPDefinition,
    *,
    action_override: str | None = None,
    rationale_override: str | None = None,
) -> AgentPlan:
    execution_directives = dict(sop.execution_defaults)
    if sop.stage == WorkflowStage.STATIC_ANALYSIS.value:
        execution_directives["dynamic_request"] = _build_dynamic_request(context)
    candidate_sops = get_sops_for_stage(sop.stage)
    return AgentPlan(
        stage=sop.stage,
        objective=sop.objective,
        strategy_name=sop.sop_id,
        selected_skills=sop.selected_skills,
        selected_tools=sop.selected_tools,
        suggested_next_action=action_override or sop.suggested_next_action,
        rationale=rationale_override or sop.rationale,
        execution_directives=execution_directives,
        selected_sop_id=sop.sop_id,
        candidate_sop_ids=[item.sop_id for item in candidate_sops],
        llm_ready_prompt_input=_build_llm_ready_prompt_input(context, sop.stage, candidate_sops),
    )


def build_agent_plan(context: AnalysisContext, stage: str) -> AgentPlan:
    if stage == WorkflowStage.HASH_INTEL.value:
        sop = next(sop for sop in get_sops_for_stage(stage) if sop.sop_id == "hash_intel_enrichment")
        return _plan_from_sop(context, sop)

    if stage == WorkflowStage.STATIC_ANALYSIS.value:
        high_followup_sop = next(sop for sop in get_sops_for_stage(stage) if sop.sop_id == "static_to_safe_replay")
        minimum_followup_sop = next(
            sop for sop in get_sops_for_stage(stage) if sop.sop_id == "static_minimum_dynamic_path"
        )
        v2 = context.static_analysis.v2 if isinstance(context.static_analysis.v2, dict) else {}
        v2_score = v2.get("risk_score")
        if isinstance(v2_score, (int, float)) and v2_score >= 0.30:
            return _plan_from_sop(
                context,
                high_followup_sop,
                action_override="collect_more_static_and_dynamic_evidence",
                rationale_override=(
                    "Static-analysis v2 indicates that the sample deserves broader follow-up evidence collection."
                ),
            )
        return _plan_from_sop(
            context,
            minimum_followup_sop,
            action_override="keep_minimum_dynamic_path",
            rationale_override=(
                "Static-analysis evidence is present, but the minimum dynamic path remains sufficient for phase 1."
            ),
        )

    if stage == WorkflowStage.DYNAMIC_ANALYSIS.value:
        sop = next(sop for sop in get_sops_for_stage(stage) if sop.sop_id == "dynamic_replay_to_verdict")
        return _plan_from_sop(context, sop)

    if stage == WorkflowStage.FINAL_VERDICT.value:
        sop = next(sop for sop in get_sops_for_stage(stage) if sop.sop_id == "final_verdict_emit")
        return _plan_from_sop(context, sop)

    return AgentPlan(
        stage=stage,
        objective="No specialized planning rule exists yet.",
        strategy_name="fallback_plan",
        selected_skills=["project-memory"],
        selected_tools=["rule_based_agent"],
        suggested_next_action="no_op",
        rationale="Fallback plan.",
        llm_ready_prompt_input=_build_llm_ready_prompt_input(context, stage, []),
    )
