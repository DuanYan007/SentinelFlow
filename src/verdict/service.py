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


def _static_v2_score(context: AnalysisContext) -> float | None:
    v2 = context.static_analysis.v2
    if not isinstance(v2, dict):
        return None
    score = v2.get("risk_score")
    if isinstance(score, (int, float)):
        return float(score)
    return None


def _score_to_signal(score: float, bundle: RuntimeConfigBundle) -> str:
    if score >= bundle.static_analysis.high_score_threshold:
        return "high"
    if score >= bundle.static_analysis.medium_score_threshold:
        return "medium"
    return "low"


def run_verdict(context: AnalysisContext, bundle: RuntimeConfigBundle) -> AnalysisContext:
    vt_signal = _vt_signal(context)
    static_signal = _static_signal(context, bundle)
    static_v2_score = _static_v2_score(context) if bundle.phase1.enable_v2_verdict_signal else None
    static_v2_signal = _score_to_signal(static_v2_score, bundle) if static_v2_score is not None else "unknown"
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
    if static_v2_score is not None:
        decision_basis.append(f"Static v2 risk score={static_v2_score:.3f} ({static_v2_signal})")
    decision_basis.append("Dynamic analysis is not part of the active workflow.")

    has_static_indicators = bool(context.static_analysis.matched_features)
    effective_static_signal = static_signal
    if static_v2_score is not None:
        if static_v2_signal == "high" or static_signal == "high":
            effective_static_signal = "high"
        elif static_v2_signal == "medium" or static_signal == "medium":
            effective_static_signal = "medium"
        else:
            effective_static_signal = "low"

    if vt_signal == "high" or effective_static_signal == "high":
        label = FinalLabel.MALICIOUS.value
    elif vt_signal == "medium" or effective_static_signal == "medium":
        label = FinalLabel.SUSPICIOUS.value
    elif has_static_indicators:
        label = FinalLabel.SUSPICIOUS.value
    elif context.threat_intel.status == "error":
        label = FinalLabel.SUSPICIOUS.value
    else:
        label = FinalLabel.BENIGN.value

    vt_score_map = {"high": 1.0, "medium": 0.6, "low": 0.2, "unknown": 0.0}
    effective_static_score = context.static_analysis.risk_score
    if static_v2_score is not None:
        effective_static_score = max(effective_static_score, static_v2_score)
    final_score = round(
        min(1.0, 0.4 * vt_score_map.get(vt_signal, 0.0) + 0.6 * effective_static_score),
        3,
    )

    context.verdict.final_label = label
    context.verdict.final_score = final_score
    context.verdict.decision_basis = decision_basis
    context.verdict.explanation = "The current verdict is based on available threat-intelligence and static evidence."

    if context.workflow_status.status == WorkflowState.INITIALIZED.value:
        context.workflow_status.status = WorkflowState.COMPLETED_DEGRADED.value
        context.workflow_status.message = "Workflow completed without dynamic analysis."
    return context
