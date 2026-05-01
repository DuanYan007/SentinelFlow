from __future__ import annotations

import math
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pefile  # type: ignore

from config.static_config import StaticConfig
from core.constants import DEFAULT_CONFIGS_DIR
from core.enums import ModuleStatus
from models.static_analysis_v2 import (
    EvidenceRef,
    ImportCategoryAggregate,
    ModuleScoreContribution,
    PEBasicAggregate,
    ParserWarningInfo,
    PefileBasicHeaders,
    PefileImportOutput,
    PefileIndicator,
    PefileSectionOutput,
    RawEvidenceItem,
    RuleScoreContribution,
    SectionFeaturesAggregate,
    StaticAnalysisResultV2,
    StaticAnalysisSummaryV2,
    create_default_static_analysis_result_v2,
)
from .rule_loader import load_static_rule_bundle
from .rule_matcher import match_rules

_SECTION_FLAG_MAP = {
    0x20000000: "execute",
    0x40000000: "read",
    0x80000000: "write",
}

_FILE_CHARACTERISTICS_MAP = {
    0x0002: "executable_image",
    0x0020: "large_address_aware",
    0x0100: "32bit_machine",
    0x0200: "debug_stripped",
    0x2000: "dll",
}

_DLL_CHARACTERISTICS_MAP = {
    0x0020: "high_entropy_va",
    0x0040: "dynamic_base",
    0x0080: "force_integrity",
    0x0100: "nx_compat",
    0x0200: "no_isolation",
    0x0400: "no_seh",
    0x0800: "no_bind",
    0x1000: "app_container",
    0x2000: "wdm_driver",
    0x4000: "guard_cf",
    0x8000: "terminal_server_aware",
}

_SUBSYSTEM_MAP = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    14: "xbox",
    16: "windows_boot_application",
}

_SUSPICIOUS_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".packed",
    ".petite",
    ".boom",
}

_DEFAULT_STRING_KEYWORDS = {
    "ransom_note": ["decrypt", "bitcoin", "recover your files", "your files"],
    "extension_change": [".locked", ".encrypted", ".crypt", ".enc"],
    "backup_delete": ["vssadmin", "delete shadows", "wmic shadowcopy delete"],
    "recovery_disable": ["bcdedit", "recoveryenabled", "bootstatuspolicy"],
    "onion_or_wallet": [".onion", "wallet", "monero", "btc", "xmr"],
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _extract_strings(sample_path: Path, binary: str) -> list[str]:
    completed = subprocess.run(
        [binary, "-a", str(sample_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "strings failed")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _match_keywords(strings_output: list[str], config_keywords: dict) -> dict[str, list[str]]:
    matched: dict[str, list[str]] = {}
    lowered_strings = [item.lower() for item in strings_output]
    for category, keywords in config_keywords.items():
        hits: list[str] = []
        for keyword in keywords:
            key_lower = keyword.lower()
            if any(key_lower in item for item in lowered_strings):
                hits.append(keyword)
        matched[category] = sorted(set(hits))
    return matched


def _decode_flags(value: int, mapping: dict[int, str]) -> list[str]:
    return [name for bit, name in mapping.items() if value & bit]


def _safe_compile_time(timestamp: int) -> str:
    if timestamp <= 0:
        return ""
    try:
        return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def _machine_name(machine: int) -> str:
    known = {
        0x014C: "i386",
        0x8664: "amd64",
        0x01C0: "arm",
        0xAA64: "arm64",
    }
    return known.get(machine, hex(machine))


def _bitness_name(optional_magic: int) -> str:
    if optional_magic == 0x20B:
        return "pe32+"
    if optional_magic == 0x10B:
        return "pe32"
    return hex(optional_magic)


def _add_raw_evidence(
    result: StaticAnalysisResultV2,
    *,
    evidence_id: str,
    evidence_type: str,
    path: str,
    value: str,
    source_section: str,
    note: str,
    tags: list[str],
    confidence: float = 1.0,
    parser_meta: dict | None = None,
) -> EvidenceRef:
    result.raw_evidence.append(
        RawEvidenceItem(
            evidence_id=evidence_id,
            tool="pefile",
            type=evidence_type,
            path=path,
            value=value,
            source_section=source_section,
            note=note,
            tags=tags,
            confidence=confidence,
            parser_meta=parser_meta or {},
        )
    )
    return EvidenceRef(
        tool="pefile",
        evidence_id=evidence_id,
        path=path,
        value=value,
        category="",
        rule_id="",
    )


def _build_basic_headers(pe: pefile.PE) -> tuple[PefileBasicHeaders, list[str]]:
    suspicious_fields: list[str] = []
    compile_time = _safe_compile_time(pe.FILE_HEADER.TimeDateStamp)
    if not compile_time:
        suspicious_fields.append("compile_time")
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
        suspicious_fields.append("entry_point")

    headers = PefileBasicHeaders(
        machine=_machine_name(pe.FILE_HEADER.Machine),
        pe32_or_pe32plus=_bitness_name(pe.OPTIONAL_HEADER.Magic),
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        entry_point=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        subsystem=_SUBSYSTEM_MAP.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)),
        compile_time=compile_time,
        characteristics=_decode_flags(pe.FILE_HEADER.Characteristics, _FILE_CHARACTERISTICS_MAP),
        dll_characteristics=_decode_flags(pe.OPTIONAL_HEADER.DllCharacteristics, _DLL_CHARACTERISTICS_MAP),
        section_alignment=int(pe.OPTIONAL_HEADER.SectionAlignment),
        file_alignment=int(pe.OPTIONAL_HEADER.FileAlignment),
        image_size=int(pe.OPTIONAL_HEADER.SizeOfImage),
    )
    return headers, suspicious_fields


def _build_sections(pe: pefile.PE, entropy_threshold: float) -> tuple[list[PefileSectionOutput], SectionFeaturesAggregate]:
    outputs: list[PefileSectionOutput] = []
    hit_section_names: list[str] = []
    entropy_values: list[float] = []
    high_entropy_count = 0
    writable_executable_count = 0
    abnormal_name_count = 0
    empty_or_tiny_count = 0
    abnormal_permission_combo_count = 0

    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
        characteristics_value = int(section.Characteristics)
        permissions = _decode_flags(characteristics_value, _SECTION_FLAG_MAP)
        is_executable = "execute" in permissions
        is_writable = "write" in permissions
        raw_size = int(section.SizeOfRawData)
        virtual_size = int(section.Misc_VirtualSize)
        try:
            data = section.get_data()
        except Exception:
            data = b""
        entropy = round(_shannon_entropy(data), 3)
        entropy_values.append(entropy)

        anomalies: list[str] = []
        if entropy >= entropy_threshold:
            anomalies.append("high_entropy")
            high_entropy_count += 1
        if is_executable and is_writable:
            anomalies.append("writable_executable")
            writable_executable_count += 1
            abnormal_permission_combo_count += 1
        if name.lower() in _SUSPICIOUS_SECTION_NAMES:
            anomalies.append("suspicious_section_name")
            abnormal_name_count += 1
            hit_section_names.append(name)
        if raw_size == 0 or virtual_size <= 32:
            anomalies.append("empty_or_tiny")
            empty_or_tiny_count += 1

        outputs.append(
            PefileSectionOutput(
                name=name,
                virtual_size=virtual_size,
                raw_size=raw_size,
                entropy=entropy,
                characteristics=[hex(characteristics_value)],
                permissions=permissions,
                is_executable=is_executable,
                is_writable=is_writable,
                pointer_to_raw_data=int(section.PointerToRawData),
                virtual_address=int(section.VirtualAddress),
                anomalies=anomalies,
            )
        )

    distribution_summary = {
        "section_count": len(outputs),
        "max_entropy": max(entropy_values) if entropy_values else 0.0,
        "mean_entropy": round(sum(entropy_values) / len(entropy_values), 3) if entropy_values else 0.0,
    }
    aggregate = SectionFeaturesAggregate(
        high_entropy_count=high_entropy_count,
        writable_executable_count=writable_executable_count,
        abnormal_name_count=abnormal_name_count,
        empty_or_tiny_count=empty_or_tiny_count,
        abnormal_permission_combo_count=abnormal_permission_combo_count,
        hit_section_names=sorted(set(hit_section_names)),
        distribution_summary=distribution_summary,
        summary=(
            f"sections={len(outputs)}, high_entropy={high_entropy_count}, "
            f"wx={writable_executable_count}, suspicious_names={abnormal_name_count}"
        ),
    )
    return outputs, aggregate


def _build_imports(pe: pefile.PE) -> tuple[list[PefileImportOutput], ImportCategoryAggregate]:
    outputs: list[PefileImportOutput] = []
    apis: list[str] = []
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    for entry in entries:
        dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else ""
        for imp in entry.imports:
            api_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
            apis.append(f"{dll_name}!{api_name}")
            outputs.append(
                PefileImportOutput(
                    dll=dll_name,
                    api=api_name,
                    ordinal=int(imp.ordinal) if imp.ordinal is not None else None,
                    note="Import extracted by pefile; rule categorization pending.",
                )
            )
    aggregate = ImportCategoryAggregate(
        count=len(outputs),
        matched_apis=apis[:20],
        summary=f"imports={len(outputs)}; categorization pending rules integration.",
    )
    return outputs, aggregate


def _append_rule_evidence(
    result: StaticAnalysisResultV2,
    *,
    evidence_id: str,
    path: str,
    value: str,
    source_section: str,
    note: str,
    tags: list[str],
    category: str,
    rule_id: str,
    confidence: float = 0.95,
) -> EvidenceRef:
    ref = _add_raw_evidence(
        result,
        evidence_id=evidence_id,
        evidence_type=f"{source_section}_rule_hit",
        path=path,
        value=value,
        source_section=source_section,
        note=note,
        tags=tags,
        confidence=confidence,
    )
    ref.category = category
    ref.rule_id = rule_id
    return ref


def _append_tool_evidence(
    result: StaticAnalysisResultV2,
    *,
    tool: str,
    evidence_id: str,
    path: str,
    value: str,
    source_section: str,
    note: str,
    tags: list[str],
    confidence: float = 0.9,
) -> EvidenceRef:
    result.raw_evidence.append(
        RawEvidenceItem(
            evidence_id=evidence_id,
            tool=tool,
            type=f"{source_section}_evidence",
            path=path,
            value=value,
            source_section=source_section,
            note=note,
            tags=tags,
            confidence=confidence,
            parser_meta={},
        )
    )
    return EvidenceRef(tool=tool, evidence_id=evidence_id, path=path, value=value)


def _integrate_strings_v2(
    result: StaticAnalysisResultV2,
    sample_path: Path,
    config: StaticConfig,
) -> tuple[list[str], list[EvidenceRef]]:
    keyword_config = _DEFAULT_STRING_KEYWORDS.copy()
    keyword_config.update(config.string_keyword_sets or {})

    try:
        strings_output = _extract_strings(sample_path, config.strings_binary)
    except Exception as exc:
        result.tool_outputs.strings.status = ModuleStatus.ERROR.value
        result.tool_outputs.strings.errors.append(str(exc))
        result.tool_outputs.strings.summary = "strings extraction failed"
        return [], []

    result.tools_used.append("strings")
    result.tool_outputs.strings.status = ModuleStatus.OK.value
    keyword_hits = _match_keywords(strings_output, keyword_config)
    result.tool_outputs.strings.raw_data = {
        "string_count": len(strings_output),
        "sample_strings": strings_output[:50],
        "keyword_hits": keyword_hits,
    }
    result.tool_outputs.strings.summary = (
        f"strings_ok count={len(strings_output)} matched_categories="
        f"{','.join(sorted([key for key, value in keyword_hits.items() if value])) or 'none'}"
    )

    key_hits: list[str] = []
    refs: list[EvidenceRef] = []
    for category, hits in keyword_hits.items():
        for index, hit in enumerate(hits):
            ref = _append_tool_evidence(
                result,
                tool="strings",
                evidence_id=f"strings-{category}-{index}",
                path=f"tool_outputs.strings.raw_data.keyword_hits.{category}[{index}]",
                value=hit,
                source_section="strings",
                note=f"Keyword hit in category {category}",
                tags=["strings", category],
            )
            refs.append(ref)
            key_hits.append(f"strings:{category}:{hit}")
    return key_hits, refs


def _integrate_die_v2(
    result: StaticAnalysisResultV2,
    sample_path: Path,
    config: StaticConfig,
) -> tuple[list[str], list[EvidenceRef]]:
    if not config.die_binary:
        result.tool_outputs.die.status = ModuleStatus.SKIPPED.value
        result.tool_outputs.die.summary = "die binary is not configured"
        return [], []

    try:
        completed = subprocess.run(
            [config.die_binary, str(sample_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        result.tool_outputs.die.status = ModuleStatus.PARTIAL.value
        result.tool_outputs.die.errors.append("die timed out after 5 seconds")
        result.tool_outputs.die.summary = "die execution timed out"
        return [], []
    except Exception as exc:
        result.tool_outputs.die.status = ModuleStatus.ERROR.value
        result.tool_outputs.die.errors.append(str(exc))
        result.tool_outputs.die.summary = "die execution failed"
        return [], []

    stdout_lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    stderr_lines = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
    result.tools_used.append("die")
    result.tool_outputs.die.status = ModuleStatus.OK.value if completed.returncode == 0 else ModuleStatus.PARTIAL.value
    result.tool_outputs.die.raw_data = {
        "returncode": completed.returncode,
        "stdout_lines": stdout_lines[:80],
        "stderr_lines": stderr_lines[:40],
    }
    if completed.returncode != 0 and stderr_lines:
        result.tool_outputs.die.errors.extend(stderr_lines[:10])

    key_hits: list[str] = []
    refs: list[EvidenceRef] = []
    interesting = [
        line for line in stdout_lines
        if any(token in line.lower() for token in ["compiler", "packer", "protector", "linker", "installer"])
    ]
    for index, line in enumerate(interesting[:10]):
        ref = _append_tool_evidence(
            result,
            tool="die",
            evidence_id=f"die-line-{index}",
            path=f"tool_outputs.die.raw_data.stdout_lines[{index}]",
            value=line,
            source_section="die",
            note="Interesting DIE identification line",
            tags=["die", "signature"],
        )
        refs.append(ref)
        key_hits.append(f"die:{line}")

    result.tool_outputs.die.summary = (
        f"die_status={result.tool_outputs.die.status} stdout_lines={len(stdout_lines)} "
        f"interesting_lines={len(interesting)}"
    )
    return key_hits, refs


def _apply_section_rule_hits(
    result: StaticAnalysisResultV2,
    sections: list[PefileSectionOutput],
    config_dir: str,
) -> tuple[list[str], list[EvidenceRef]]:
    bundle = load_static_rule_bundle(config_dir)
    section_matches = match_rules(bundle.section_rules, sections)
    key_hits: list[str] = []
    refs: list[EvidenceRef] = []
    hit_names: list[str] = []

    for index, matches in section_matches.items():
        if not matches:
            continue
        section = sections[index]
        hit_names.append(section.name)
        for match in matches:
            evidence_ref = _append_rule_evidence(
                result,
                evidence_id=f"section-rule-{index}-{match.rule_id}",
                path=f"tool_outputs.pefile.sections[{index}]",
                value=section.name,
                source_section="sections",
                note=match.reason,
                tags=["section", match.category, match.rule_id],
                category=match.category,
                rule_id=match.rule_id,
            )
            refs.append(evidence_ref)
            key_hits.append(f"section_rule:{match.rule_id}:{section.name}")

    result.normalized_features.section_features.hit_section_names = sorted(set(hit_names))
    result.normalized_features.section_features.top_evidence_refs = refs[:10]
    result.normalized_features.section_features.summary = (
        f"section_rules_hit={len(refs)}; hit_sections={len(set(hit_names))}"
    )
    return key_hits, refs


def _apply_import_rule_hits(
    result: StaticAnalysisResultV2,
    imports: list[PefileImportOutput],
    config_dir: str,
) -> tuple[list[str], list[EvidenceRef]]:
    bundle = load_static_rule_bundle(config_dir)
    import_matches = match_rules(bundle.import_rules, imports)
    key_hits: list[str] = []
    refs: list[EvidenceRef] = []
    category_map: dict[str, ImportCategoryAggregate] = {}

    for index, matches in import_matches.items():
        if not matches:
            continue
        import_item = imports[index]
        primary = matches[0]
        import_item.category = primary.category
        import_item.matched_rule_id = primary.rule_id
        import_item.risk_weight = primary.risk_weight

        evidence_ref = _append_rule_evidence(
            result,
            evidence_id=f"import-rule-{index}-{primary.rule_id}",
            path=f"tool_outputs.pefile.imports[{index}]",
            value=f"{import_item.dll}!{import_item.api}",
            source_section="imports",
            note=primary.reason,
            tags=["import", primary.category, primary.rule_id],
            category=primary.category,
            rule_id=primary.rule_id,
        )
        import_item.evidence_ref = evidence_ref
        import_item.note = primary.reason
        refs.append(evidence_ref)
        key_hits.append(f"import_rule:{primary.rule_id}:{import_item.api}")

        aggregate = category_map.setdefault(primary.category, ImportCategoryAggregate())
        aggregate.count += 1
        aggregate.matched_apis.append(f"{import_item.dll}!{import_item.api}")
        aggregate.matched_rule_ids.append(primary.rule_id)
        aggregate.risk_contribution += primary.risk_weight
        aggregate.top_evidence_refs.append(evidence_ref)

    for category, aggregate in category_map.items():
        aggregate.matched_apis = sorted(set(aggregate.matched_apis))
        aggregate.matched_rule_ids = sorted(set(aggregate.matched_rule_ids))
        aggregate.summary = (
            f"category={category}, count={aggregate.count}, rules={','.join(aggregate.matched_rule_ids)}"
        )
        result.normalized_features.import_features.categories[category] = aggregate

    if category_map:
        category_list = sorted(category_map)
        result.normalized_features.import_features.summary = (
            f"categorized_import_hits={sum(item.count for item in category_map.values())}; "
            f"categories={','.join(category_list)}"
        )
    else:
        result.normalized_features.import_features.summary = "categorized_import_hits=0"

    return key_hits, refs


def _populate_v2_score_breakdown(result: StaticAnalysisResultV2) -> None:
    section_refs = result.normalized_features.section_features.top_evidence_refs
    import_refs = [
        ref
        for aggregate in result.normalized_features.import_features.categories.values()
        for ref in aggregate.top_evidence_refs
    ]

    section_raw = min(1.0, 0.12 * len(section_refs))
    import_raw = min(1.0, sum(item.risk_contribution for item in result.normalized_features.import_features.categories.values()))
    pe_basic_raw = min(1.0, 0.05 * len(result.normalized_features.pe_basic.suspicious_header_fields))

    result.score_breakdown.rule_scores = []

    for ref in section_refs:
        result.score_breakdown.rule_scores.append(
            RuleScoreContribution(
                module="section",
                category=ref.category,
                rule_id=ref.rule_id,
                weight_source="static-section-rules.v1",
                raw_score=1.0,
                contribution=0.12,
                max_score=1.0,
                normalization="per_hit",
                evidence_refs=[ref],
                version="static-section-rules.v1",
                reason="Section rule matched during v2 extraction.",
            )
        )

    for category, aggregate in result.normalized_features.import_features.categories.items():
        for rule_id in aggregate.matched_rule_ids:
            related_refs = [ref for ref in aggregate.top_evidence_refs if ref.rule_id == rule_id]
            result.score_breakdown.rule_scores.append(
                RuleScoreContribution(
                    module="import",
                    category=category,
                    rule_id=rule_id,
                    weight_source="static-import-rules.v1",
                    raw_score=float(aggregate.count),
                    contribution=aggregate.risk_contribution,
                    max_score=1.0,
                    normalization="category_sum_capped",
                    evidence_refs=related_refs[:5],
                    version="static-import-rules.v1",
                    reason="Import rule matched categorized API entries during v2 extraction.",
                )
            )

    if result.normalized_features.pe_basic.suspicious_header_fields:
        result.score_breakdown.rule_scores.append(
            RuleScoreContribution(
                module="pe_basic",
                category="header_anomaly",
                rule_id="PE-BASIC-HEADER",
                weight_source="built_in_header_checks",
                raw_score=float(len(result.normalized_features.pe_basic.suspicious_header_fields)),
                contribution=pe_basic_raw,
                max_score=1.0,
                normalization="count_capped",
                evidence_refs=result.normalized_features.pe_basic.top_evidence_refs[:5],
                version=result.schema_version,
                reason="Built-in PE basic header anomaly checks matched.",
            )
        )

    result.score_breakdown.module_scores = [
        ModuleScoreContribution(
            module="pe_basic",
            raw_score=pe_basic_raw,
            normalized_score=pe_basic_raw,
            module_cap=0.2,
            weight=0.2,
            final_contribution=min(0.2, pe_basic_raw * 0.2),
            evidence_refs=result.normalized_features.pe_basic.top_evidence_refs[:5],
            version=result.schema_version,
            reason="Suspicious PE header fields contribute to the v2 static score.",
        ),
        ModuleScoreContribution(
            module="section",
            raw_score=section_raw,
            normalized_score=section_raw,
            module_cap=0.35,
            weight=0.35,
            final_contribution=min(0.35, section_raw * 0.35),
            evidence_refs=result.normalized_features.section_features.top_evidence_refs[:5],
            version="static-section-rules.v1",
            reason="Section rule hits contribute to the v2 static score.",
        ),
        ModuleScoreContribution(
            module="import",
            raw_score=import_raw,
            normalized_score=min(1.0, import_raw),
            module_cap=0.45,
            weight=0.45,
            final_contribution=min(0.45, min(1.0, import_raw) * 0.45),
            evidence_refs=import_refs[:5],
            version="static-import-rules.v1",
            reason="Categorized import rule hits contribute to the v2 static score.",
        ),
    ]
    result.score_breakdown.normalization_strategy = "rule_hits_to_modules_then_weighted_caps"
    result.score_breakdown.weight_source = "static-analysis-v2-internal"
    result.risk_score = round(sum(item.final_contribution for item in result.score_breakdown.module_scores), 3)

    if result.risk_score >= 0.60:
        result.summary.risk_level = "high"
    elif result.risk_score >= 0.30:
        result.summary.risk_level = "medium"
    else:
        result.summary.risk_level = "low"


def extract_pefile_v2(
    sample_path: str | Path,
    config: StaticConfig,
    config_dir: str = DEFAULT_CONFIGS_DIR,
) -> StaticAnalysisResultV2:
    result = create_default_static_analysis_result_v2()
    result.executed = True
    result.tools_used = ["pefile"]
    result.status = ModuleStatus.OK.value
    result.summary = StaticAnalysisSummaryV2(
        risk_level="not_scored",
        short_reason="PE structure extracted into the v2 schema; rule scoring is not integrated yet.",
        tool_coverage=["pefile"],
    )

    path = Path(sample_path)
    start = time.perf_counter()

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        result.status = ModuleStatus.ERROR.value
        result.error = f"STATIC_PEFILE_V2_PARSE_FAILURE: {exc}"
        result.tool_outputs.pefile.status = ModuleStatus.ERROR.value
        result.tool_outputs.pefile.errors.append(str(exc))
        result.tool_outputs.pefile.parser_meta.source_file = str(path)
        result.tool_outputs.pefile.parser_meta.parse_status = ModuleStatus.ERROR.value
        result.tool_outputs.pefile.parser_meta.error_count = 1
        return result

    basic_headers, suspicious_fields = _build_basic_headers(pe)
    sections, section_aggregate = _build_sections(pe, config.entropy_threshold)
    imports, import_aggregate = _build_imports(pe)

    result.tool_outputs.pefile.status = ModuleStatus.OK.value
    result.tool_outputs.pefile.parser_meta.source_file = str(path)
    result.tool_outputs.pefile.parser_meta.parse_status = ModuleStatus.OK.value
    result.tool_outputs.pefile.basic_headers = basic_headers
    result.tool_outputs.pefile.sections = sections
    result.tool_outputs.pefile.imports = imports

    key_hits: list[str] = []
    evidence_refs: list[EvidenceRef] = []

    for field_name in suspicious_fields:
        value = str(getattr(basic_headers, field_name, ""))
        evidence_ref = _add_raw_evidence(
            result,
            evidence_id=f"pe-header-{field_name}",
            evidence_type="pe_header",
            path=f"tool_outputs.pefile.basic_headers.{field_name}",
            value=value,
            source_section="basic_headers",
            note="Potentially suspicious PE header field.",
            tags=["header", "suspicious"],
        )
        evidence_refs.append(evidence_ref)
        key_hits.append(f"suspicious_header:{field_name}")

    for index, section in enumerate(sections):
        if not section.anomalies:
            continue
        evidence_ref = _add_raw_evidence(
            result,
            evidence_id=f"pe-section-{index}",
            evidence_type="pe_section",
            path=f"tool_outputs.pefile.sections[{index}]",
            value=section.name,
            source_section="sections",
            note=f"Section anomalies: {', '.join(section.anomalies)}",
            tags=["section", *section.anomalies],
        )
        evidence_refs.append(evidence_ref)
        key_hits.append(f"section:{section.name}")

    if imports:
        top_import_refs: list[EvidenceRef] = []
        for index, item in enumerate(imports[:10]):
            evidence_ref = _add_raw_evidence(
                result,
                evidence_id=f"pe-import-{index}",
                evidence_type="pe_import",
                path=f"tool_outputs.pefile.imports[{index}]",
                value=f"{item.dll}!{item.api}",
                source_section="imports",
                note="Representative import kept for later rule categorization.",
                tags=["import"],
                confidence=0.9,
            )
            item.evidence_ref = evidence_ref
            top_import_refs.append(evidence_ref)
        import_aggregate.top_evidence_refs = top_import_refs

    result.normalized_features.pe_basic = PEBasicAggregate(
        architecture=basic_headers.machine,
        bitness=basic_headers.pe32_or_pe32plus,
        entry_point=basic_headers.entry_point,
        compile_time=basic_headers.compile_time,
        subsystem=basic_headers.subsystem,
        alignment_and_image_size_summary={
            "section_alignment": basic_headers.section_alignment,
            "file_alignment": basic_headers.file_alignment,
            "image_size": basic_headers.image_size,
        },
        suspicious_header_fields=suspicious_fields,
        top_evidence_refs=evidence_refs[:5],
        summary=f"{basic_headers.machine} {basic_headers.pe32_or_pe32plus} subsystem={basic_headers.subsystem}",
    )

    section_rule_hits, section_rule_refs = _apply_section_rule_hits(result, sections, config_dir)
    import_rule_hits, import_rule_refs = _apply_import_rule_hits(result, imports, config_dir)

    if not section_rule_refs:
        section_aggregate.top_evidence_refs = [ref for ref in evidence_refs if ref.evidence_id.startswith("pe-section-")][:10]
        section_aggregate.summary = (
            f"sections={len(sections)}, rule_hits=0, high_entropy={section_aggregate.high_entropy_count}"
        )
    else:
        section_aggregate.top_evidence_refs = section_rule_refs[:10]
    result.normalized_features.section_features = section_aggregate

    if not result.normalized_features.import_features.categories:
        result.normalized_features.import_features.categories["unclassified"] = import_aggregate
        result.normalized_features.import_features.summary = import_aggregate.summary

    result.tool_outputs.pefile.indicators = [
        PefileIndicator(
            name="has_high_entropy_section",
            matched=section_aggregate.high_entropy_count > 0,
            count=section_aggregate.high_entropy_count,
            key_hits=[ref.value for ref in section_aggregate.top_evidence_refs[:5]],
            risk_note="High entropy may indicate packing or encrypted payload regions.",
            evidence_refs=section_aggregate.top_evidence_refs[:5],
            rule_sources=["config:entropy_threshold"],
        ),
        PefileIndicator(
            name="has_writable_executable_section",
            matched=section_aggregate.writable_executable_count > 0,
            count=section_aggregate.writable_executable_count,
            key_hits=[ref.value for ref in section_aggregate.top_evidence_refs[:5]],
            risk_note="Writable and executable sections may indicate shellcode or unpacking behavior.",
            evidence_refs=section_aggregate.top_evidence_refs[:5],
            rule_sources=["section_anomaly:permissions"],
        ),
        PefileIndicator(
            name="has_categorized_import_hits",
            matched=bool(import_rule_refs),
            count=len(import_rule_refs),
            key_hits=import_rule_hits[:5],
            risk_note="Import rules matched categorized APIs extracted from the PE import table.",
            evidence_refs=import_rule_refs[:5] or import_aggregate.top_evidence_refs[:5],
            rule_sources=["static-import-rules.v1"],
        ),
    ]

    if result.tool_outputs.pefile.errors:
        result.tool_outputs.pefile.summary.parser_warnings.append(
            ParserWarningInfo(
                warning_id="pefile-errors-present",
                level="warning",
                message="The pefile extractor completed with recoverable parser issues.",
                source_field="tool_outputs.pefile.errors",
                parser_stage="pefile_extract",
                impact="partial_observability",
                fallback_action="Continue with available fields.",
            )
        )

    elapsed_ms = int((time.perf_counter() - start) * 1000)
    result.tool_outputs.pefile.parser_meta.parse_time_ms = elapsed_ms
    result.tool_outputs.pefile.parser_meta.schema_version = result.schema_version
    result.tool_outputs.pefile.summary.risk_level = "not_scored"
    result.tool_outputs.pefile.summary.short_reason = "Pefile extraction and section/import rule matching completed; scoring is pending."
    result.tool_outputs.pefile.summary.rule_versions = ["static-section-rules.v1", "static-import-rules.v1"]
    _populate_v2_score_breakdown(result)
    strings_key_hits, strings_refs = _integrate_strings_v2(result, path, config)
    die_key_hits, die_refs = _integrate_die_v2(result, path, config)

    result.tool_outputs.pefile.summary.key_hits = (
        key_hits + section_rule_hits + import_rule_hits + strings_key_hits + die_key_hits
    )[:10]
    result.tool_outputs.pefile.summary.evidence_refs = (
        evidence_refs + section_rule_refs + import_rule_refs + strings_refs + die_refs
    )[:10]
    result.summary.key_hits = result.tool_outputs.pefile.summary.key_hits[:]
    result.summary.top_evidence_refs = result.tool_outputs.pefile.summary.evidence_refs[:]
    result.summary.parser_warnings = result.tool_outputs.pefile.summary.parser_warnings
    result.summary.tool_coverage = result.tools_used[:]

    return result
