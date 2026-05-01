from dataclasses import dataclass, field

from core.enums import FinalLabel


@dataclass
class VerdictResult:
    final_label: str = FinalLabel.SUSPICIOUS.value
    final_score: float = 0.0
    decision_basis: list[str] = field(default_factory=list)
    explanation: str = ""

