from config.loader import RuntimeConfigBundle
from core.enums import FinalLabel, WorkflowState
from models.analysis_context import AnalysisContext


def _vt_signal(context: AnalysisContext) -> str:
    if context.threat_intel.status == "error":
        return "unknown"
    return context.threat_intel.vt_signal or "unknown"


def _static_signal(context: AnalysisContext, bundle: RuntimeConfigBundle) -> str:
    score = context.static_analysis.risk_score
    if score >= bundle.static_analysis.high_score_threshold:
        return "high"
    if score >= bundle.static_analysis.medium_score_threshold:
        return "medium"
    return "low"


def run_verdict(context: AnalysisContext, bundle: RuntimeConfigBundle) -> AnalysisContext:
    vt_signal = _vt_signal(context)
    static_signal = _static_signal(context, bundle)
    dynamic_score = context.dynamic_analysis.risk_score
    if dynamic_score >= bundle.static_analysis.high_score_threshold:
        dynamic_signal = "high"
    elif dynamic_score >= bundle.static_analysis.medium_score_threshold:
        dynamic_signal = "medium"
    else:
        dynamic_signal = "low"
    decision_basis: list[str] = []

    if context.threat_intel.status == "ok" and context.threat_intel.matched:
        decision_basis.append(
            f"VT malicious count={context.threat_intel.malicious_count}, signal={vt_signal}"
        )
    elif context.threat_intel.status == "skipped":
        decision_basis.append("VT was skipped by local configuration")
    elif context.threat_intel.status == "error":
        decision_basis.append("VT query failed or credentials were unavailable")
    else:
        decision_basis.append("VT returned no match")

    decision_basis.append(f"Static risk score={context.static_analysis.risk_score:.3f} ({static_signal})")
    if context.dynamic_analysis.status == "skipped":
        decision_basis.append("Dynamic analysis was skipped by config")
    else:
        decision_basis.append(f"Dynamic risk score={dynamic_score:.3f} ({dynamic_signal})")

    has_static_indicators = bool(context.static_analysis.matched_features)

    if vt_signal == "high" or static_signal == "high" or dynamic_signal == "high":
        label = FinalLabel.MALICIOUS.value
    elif vt_signal == "medium" or static_signal == "medium" or dynamic_signal == "medium":
        label = FinalLabel.SUSPICIOUS.value
    elif has_static_indicators:
        label = FinalLabel.SUSPICIOUS.value
    elif context.threat_intel.status == "error":
        label = FinalLabel.SUSPICIOUS.value
    else:
        label = FinalLabel.BENIGN.value

    vt_score_map = {"high": 1.0, "medium": 0.6, "low": 0.2, "unknown": 0.0}
    final_score = round(
        min(1.0, 0.3 * vt_score_map.get(vt_signal, 0.0) + 0.3 * context.static_analysis.risk_score + 0.4 * dynamic_score),
        3,
    )

    context.verdict.final_label = label
    context.verdict.final_score = final_score
    context.verdict.decision_basis = decision_basis
    context.verdict.explanation = (
        "The current verdict is based on available threat-intelligence, static evidence, and dynamic evidence when configured."
    )

    if context.workflow_status.status == WorkflowState.INITIALIZED.value:
        context.workflow_status.status = WorkflowState.COMPLETED_DEGRADED.value
        context.workflow_status.message = "Workflow completed without dynamic analysis."
    return context
