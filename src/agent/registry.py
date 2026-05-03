from __future__ import annotations

from dataclasses import dataclass, field

from core.enums import WorkflowStage


@dataclass(frozen=True)
class AgentSkillDefinition:
    skill_id: str
    description: str
    kind: str = "internal"


@dataclass(frozen=True)
class AgentSOPDefinition:
    sop_id: str
    stage: str
    objective: str
    description: str
    selected_skills: list[str] = field(default_factory=list)
    selected_tools: list[str] = field(default_factory=list)
    suggested_next_action: str = ""
    rationale: str = ""
    execution_defaults: dict = field(default_factory=dict)


def get_skill_registry() -> dict[str, AgentSkillDefinition]:
    return {
        "project-memory": AgentSkillDefinition(
            skill_id="project-memory",
            description="Load and refresh long-term project memory before key workflow decisions.",
        ),
        "threat-intel-triage": AgentSkillDefinition(
            skill_id="threat-intel-triage",
            description="Interpret hash-intelligence results and normalize early confidence.",
        ),
        "static-pe-triage": AgentSkillDefinition(
            skill_id="static-pe-triage",
            description="Interpret PE static evidence and score suspicious indicators.",
        ),
        "dynamic-behavior-triage": AgentSkillDefinition(
            skill_id="dynamic-behavior-triage",
            description="Interpret dynamic behavior evidence and summarize impact.",
        ),
        "safe-replay-loader": AgentSkillDefinition(
            skill_id="safe-replay-loader",
            description="Load sample-specific dynamic replay artifacts without executing malware.",
        ),
        "verdict-summarizer": AgentSkillDefinition(
            skill_id="verdict-summarizer",
            description="Summarize multi-stage evidence into the final conclusion.",
        ),
    }


def get_sop_registry() -> dict[str, AgentSOPDefinition]:
    return {
        "hash_intel_enrichment": AgentSOPDefinition(
            sop_id="hash_intel_enrichment",
            stage=WorkflowStage.HASH_INTEL.value,
            objective="Collect initial evidence and choose the first deep-analysis path.",
            description="Use threat intelligence as the first normalization step before static analysis.",
            selected_skills=["project-memory", "threat-intel-triage"],
            selected_tools=["virustotal", "rule_based_agent"],
            suggested_next_action="continue_to_static",
            rationale="Phase 1 always keeps the static branch in the workflow after hash-intelligence handling.",
            execution_defaults={
                "workflow_transition": "static_analysis",
                "preserve_full_chain": True,
            },
        ),
        "static_to_safe_replay": AgentSOPDefinition(
            sop_id="static_to_safe_replay",
            stage=WorkflowStage.STATIC_ANALYSIS.value,
            objective="Interpret static evidence and route the sample into the dynamic branch.",
            description="Prefer structured static evidence, then request a safe replay artifact for dynamic follow-up.",
            selected_skills=["project-memory", "static-pe-triage", "safe-replay-loader"],
            selected_tools=["pefile", "strings", "die", "rule_based_agent"],
            suggested_next_action="collect_more_static_and_dynamic_evidence",
            rationale="Static evidence should be carried into a safe dynamic follow-up path before real sandbox execution exists.",
            execution_defaults={
                "workflow_transition": "dynamic_analysis",
                "dynamic_mode": "safe_replay",
            },
        ),
        "static_minimum_dynamic_path": AgentSOPDefinition(
            sop_id="static_minimum_dynamic_path",
            stage=WorkflowStage.STATIC_ANALYSIS.value,
            objective="Interpret static evidence and keep the minimum dynamic branch alive.",
            description="Use the minimum dynamic path when static evidence is weak but the phase-1 full-chain policy still applies.",
            selected_skills=["project-memory", "static-pe-triage"],
            selected_tools=["pefile", "strings", "rule_based_agent"],
            suggested_next_action="keep_minimum_dynamic_path",
            rationale="Phase 1 still exercises the dynamic branch even when static evidence is limited.",
            execution_defaults={
                "workflow_transition": "dynamic_analysis",
                "dynamic_mode": "safe_replay",
            },
        ),
        "dynamic_replay_to_verdict": AgentSOPDefinition(
            sop_id="dynamic_replay_to_verdict",
            stage=WorkflowStage.DYNAMIC_ANALYSIS.value,
            objective="Interpret dynamic behavior evidence and decide whether verdict evidence is sufficient.",
            description="Consume replay or event-log evidence, then move the workflow to the verdict stage.",
            selected_skills=["project-memory", "dynamic-behavior-triage"],
            selected_tools=["sample_replay_adapter", "event_log_adapter", "rule_based_agent"],
            suggested_next_action="produce_final_verdict",
            rationale="The current phase-1 workflow emits the final result after the dynamic branch.",
            execution_defaults={
                "workflow_transition": "final_verdict",
                "allow_missing_dynamic_artifact": True,
            },
        ),
        "final_verdict_emit": AgentSOPDefinition(
            sop_id="final_verdict_emit",
            stage=WorkflowStage.FINAL_VERDICT.value,
            objective="Emit the final verdict with normalized evidence context.",
            description="Summarize the current multi-stage evidence into the final result object.",
            selected_skills=["project-memory", "verdict-summarizer"],
            selected_tools=["rule_based_agent"],
            suggested_next_action="workflow_complete",
            rationale="The workflow has enough normalized evidence to emit a verdict in the current implementation round.",
            execution_defaults={},
        ),
    }


def get_sops_for_stage(stage: str) -> list[AgentSOPDefinition]:
    return [sop for sop in get_sop_registry().values() if sop.stage == stage]
