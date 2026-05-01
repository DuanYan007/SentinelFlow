from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core.enums import ModuleStatus

STATIC_ANALYSIS_V2_SCHEMA_VERSION = "static-analysis-v2"


@dataclass
class EvidenceRef:
    tool: str = ""
    evidence_id: str = ""
    path: str = ""
    value: str = ""
    category: str = ""
    rule_id: str = ""


@dataclass
class ParserWarningInfo:
    warning_id: str = ""
    level: str = ""
    message: str = ""
    source_field: str = ""
    parser_stage: str = ""
    impact: str = ""
    fallback_action: str = ""
    evidence_ref: EvidenceRef | None = None


@dataclass
class RawEvidenceItem:
    evidence_id: str = ""
    tool: str = ""
    type: str = ""
    path: str = ""
    value: str = ""
    source_section: str = ""
    note: str = ""
    tags: list[str] = field(default_factory=list)
    confidence: float = 1.0
    parser_meta: dict = field(default_factory=dict)


@dataclass
class ToolParserMeta:
    tool_name: str = ""
    tool_version: str = ""
    parse_status: str = ModuleStatus.SKIPPED.value
    parse_time_ms: int = 0
    warning_count: int = 0
    error_count: int = 0
    source_file: str = ""
    parser_flags: list[str] = field(default_factory=list)
    schema_version: str = STATIC_ANALYSIS_V2_SCHEMA_VERSION


@dataclass
class PefileBasicHeaders:
    machine: str = ""
    pe32_or_pe32plus: str = ""
    image_base: int = 0
    entry_point: int = 0
    subsystem: str = ""
    compile_time: str = ""
    characteristics: list[str] = field(default_factory=list)
    dll_characteristics: list[str] = field(default_factory=list)
    section_alignment: int = 0
    file_alignment: int = 0
    image_size: int = 0


@dataclass
class PefileSectionOutput:
    name: str = ""
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    characteristics: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    is_executable: bool = False
    is_writable: bool = False
    pointer_to_raw_data: int = 0
    virtual_address: int = 0
    anomalies: list[str] = field(default_factory=list)


@dataclass
class PefileImportOutput:
    dll: str = ""
    api: str = ""
    ordinal: int | None = None
    category: str = ""
    matched_rule_id: str = ""
    risk_weight: float = 0.0
    evidence_ref: EvidenceRef | None = None
    note: str = ""


@dataclass
class PefileIndicator:
    name: str = ""
    matched: bool = False
    count: int = 0
    key_hits: list[str] = field(default_factory=list)
    risk_note: str = ""
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    rule_sources: list[str] = field(default_factory=list)


@dataclass
class ToolOutputSummary:
    risk_level: str = ""
    short_reason: str = ""
    key_hits: list[str] = field(default_factory=list)
    parser_warnings: list[ParserWarningInfo] = field(default_factory=list)
    rule_versions: list[str] = field(default_factory=list)
    evidence_refs: list[EvidenceRef] = field(default_factory=list)


@dataclass
class GenericToolOutput:
    tool_name: str = ""
    status: str = ModuleStatus.SKIPPED.value
    raw_data: dict = field(default_factory=dict)
    summary: str = ""
    errors: list[str] = field(default_factory=list)


@dataclass
class PefileToolOutput:
    status: str = ModuleStatus.SKIPPED.value
    errors: list[str] = field(default_factory=list)
    parser_meta: ToolParserMeta = field(default_factory=lambda: ToolParserMeta(tool_name="pefile"))
    basic_headers: PefileBasicHeaders = field(default_factory=PefileBasicHeaders)
    sections: list[PefileSectionOutput] = field(default_factory=list)
    imports: list[PefileImportOutput] = field(default_factory=list)
    indicators: list[PefileIndicator] = field(default_factory=list)
    summary: ToolOutputSummary = field(default_factory=ToolOutputSummary)


@dataclass
class StaticToolOutputs:
    pefile: PefileToolOutput = field(default_factory=PefileToolOutput)
    strings: GenericToolOutput = field(default_factory=lambda: GenericToolOutput(tool_name="strings"))
    die: GenericToolOutput = field(default_factory=lambda: GenericToolOutput(tool_name="die"))
    additional_tools: dict[str, GenericToolOutput] = field(default_factory=dict)


@dataclass
class ImportCategoryAggregate:
    count: int = 0
    matched_apis: list[str] = field(default_factory=list)
    matched_rule_ids: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0
    top_evidence_refs: list[EvidenceRef] = field(default_factory=list)
    summary: str = ""


@dataclass
class ImportFeaturesAggregate:
    categories: dict[str, ImportCategoryAggregate] = field(default_factory=dict)
    summary: str = ""


@dataclass
class SectionFeaturesAggregate:
    high_entropy_count: int = 0
    writable_executable_count: int = 0
    abnormal_name_count: int = 0
    empty_or_tiny_count: int = 0
    abnormal_permission_combo_count: int = 0
    hit_section_names: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0
    top_evidence_refs: list[EvidenceRef] = field(default_factory=list)
    distribution_summary: dict = field(default_factory=dict)
    summary: str = ""


@dataclass
class PEBasicAggregate:
    architecture: str = ""
    bitness: str = ""
    entry_point: int = 0
    compile_time: str = ""
    subsystem: str = ""
    alignment_and_image_size_summary: dict = field(default_factory=dict)
    suspicious_header_fields: list[str] = field(default_factory=list)
    top_evidence_refs: list[EvidenceRef] = field(default_factory=list)
    summary: str = ""


@dataclass
class StaticNormalizedFeatures:
    pe_basic: PEBasicAggregate = field(default_factory=PEBasicAggregate)
    section_features: SectionFeaturesAggregate = field(default_factory=SectionFeaturesAggregate)
    import_features: ImportFeaturesAggregate = field(default_factory=ImportFeaturesAggregate)


@dataclass
class RuleScoreContribution:
    module: str = ""
    category: str = ""
    rule_id: str = ""
    weight_source: str = ""
    raw_score: float = 0.0
    contribution: float = 0.0
    max_score: float = 0.0
    normalization: str = ""
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    version: str = ""
    reason: str = ""


@dataclass
class ModuleScoreContribution:
    module: str = ""
    raw_score: float = 0.0
    normalized_score: float = 0.0
    module_cap: float = 0.0
    weight: float = 0.0
    final_contribution: float = 0.0
    evidence_refs: list[EvidenceRef] = field(default_factory=list)
    version: str = ""
    reason: str = ""


@dataclass
class StaticScoreBreakdown:
    module_scores: list[ModuleScoreContribution] = field(default_factory=list)
    rule_scores: list[RuleScoreContribution] = field(default_factory=list)
    normalization_strategy: str = ""
    weight_source: str = ""
    version: str = STATIC_ANALYSIS_V2_SCHEMA_VERSION


@dataclass
class StaticAnalysisSummaryV2:
    risk_level: str = ""
    short_reason: str = ""
    key_hits: list[str] = field(default_factory=list)
    top_evidence_refs: list[EvidenceRef] = field(default_factory=list)
    parser_warnings: list[ParserWarningInfo] = field(default_factory=list)
    tool_coverage: list[str] = field(default_factory=list)
    summary_version: str = STATIC_ANALYSIS_V2_SCHEMA_VERSION


@dataclass
class StaticAnalysisResultV2:
    schema_version: str = STATIC_ANALYSIS_V2_SCHEMA_VERSION
    executed: bool = False
    tools_used: list[str] = field(default_factory=list)
    tool_outputs: StaticToolOutputs = field(default_factory=StaticToolOutputs)
    raw_evidence: list[RawEvidenceItem] = field(default_factory=list)
    normalized_features: StaticNormalizedFeatures = field(default_factory=StaticNormalizedFeatures)
    score_breakdown: StaticScoreBreakdown = field(default_factory=StaticScoreBreakdown)
    summary: StaticAnalysisSummaryV2 = field(default_factory=StaticAnalysisSummaryV2)
    risk_score: float = 0.0
    status: str = ModuleStatus.SKIPPED.value
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def create_default_static_analysis_result_v2() -> StaticAnalysisResultV2:
    return StaticAnalysisResultV2()
