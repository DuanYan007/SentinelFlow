from dataclasses import dataclass

from core.enums import ModuleStatus


@dataclass
class ThreatIntelResult:
    source: str = "virustotal"
    query_hash_type: str = ""
    query_hash_value: str = ""
    matched: bool = False
    vt_signal: str = "unknown"
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    reputation: int = 0
    label: str = "unknown"
    permalink: str = ""
    raw_summary: str = ""
    status: str = ModuleStatus.SKIPPED.value
    error: str | None = None

