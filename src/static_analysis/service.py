from __future__ import annotations

import math
import subprocess
from pathlib import Path

import pefile  # type: ignore

from config.loader import RuntimeConfigBundle
from core.enums import ModuleStatus
from models.analysis_context import AnalysisContext
from .pefile_extractor import extract_pefile_v2

SUSPICIOUS_IMPORTS = {
    "crypto": {
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptEncrypt",
        "CryptGenKey",
        "BCryptEncrypt",
        "BCryptGenRandom",
    },
    "filesystem": {
        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "MoveFileA",
        "MoveFileW",
        "MoveFileExA",
        "MoveFileExW",
        "FindFirstFileA",
        "FindFirstFileW",
        "FindNextFileA",
        "FindNextFileW",
    },
    "process": {
        "CreateProcessA",
        "CreateProcessW",
        "ShellExecuteA",
        "ShellExecuteW",
        "WinExec",
    },
    "registry": {
        "RegCreateKeyA",
        "RegCreateKeyW",
        "RegSetValueA",
        "RegSetValueW",
        "RegSetValueExA",
        "RegSetValueExW",
    },
    "recovery": {
        "Wow64DisableWow64FsRedirection",
    },
}

DEFAULT_KEYWORDS = {
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


def _extract_strings(sample_path: Path) -> list[str]:
    completed = subprocess.run(
        ["/usr/bin/strings", "-a", str(sample_path)],
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


def _section_features(pe: pefile.PE, entropy_threshold: float) -> tuple[dict, list[float]]:
    entropies: list[float] = []
    high_entropy_sections = 0
    for section in pe.sections:
        try:
            data = section.get_data()
        except Exception:
            data = b""
        entropy = _shannon_entropy(data)
        entropies.append(round(entropy, 3))
        if entropy >= entropy_threshold:
            high_entropy_sections += 1
    pe_features = {
        "section_count": len(pe.sections),
        "high_entropy_sections": high_entropy_sections,
        "packed_or_obfuscated": high_entropy_sections >= 2,
        "suspicious_timestamp": pe.FILE_HEADER.TimeDateStamp == 0,
        "entrypoint_anomaly": pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0,
        "section_entropies": entropies,
    }
    return pe_features, entropies


def _import_features(pe: pefile.PE) -> tuple[dict, list[str]]:
    categories = {key: [] for key in SUSPICIOUS_IMPORTS}
    matched_features: list[str] = []
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    for entry in entries:
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode("utf-8", errors="ignore")
            for category, candidates in SUSPICIOUS_IMPORTS.items():
                if name in candidates:
                    categories[category].append(name)
    if categories["crypto"]:
        matched_features.append("imports_crypto_api")
    if categories["recovery"]:
        matched_features.append("imports_shadowcopy_or_recovery_api")
    if categories["filesystem"]:
        matched_features.append("imports_filesystem_api_cluster")
    import_features = {
        "crypto_api_count": len(categories["crypto"]),
        "filesystem_api_count": len(categories["filesystem"]),
        "process_api_count": len(categories["process"]),
        "registry_api_count": len(categories["registry"]),
        "shadowcopy_or_recovery_api_present": bool(categories["recovery"]),
        "matched_imports": categories,
    }
    return import_features, matched_features


def _normalize_string_features(keyword_hits: dict[str, list[str]]) -> tuple[dict, list[str]]:
    matched_features: list[str] = []
    mapping = {
        "ransom_note": "contains_ransom_note_keyword",
        "extension_change": "contains_extension_change_keyword",
        "backup_delete": "contains_backup_delete_command",
        "recovery_disable": "contains_recovery_disable_command",
        "onion_or_wallet": "contains_onion_or_wallet_indicator",
    }
    for category, feature_name in mapping.items():
        if keyword_hits.get(category):
            matched_features.append(feature_name)
    string_features = {
        "ransom_note_keywords": keyword_hits.get("ransom_note", []),
        "extension_change_keywords": keyword_hits.get("extension_change", []),
        "cmd_keywords": sorted(keyword_hits.get("backup_delete", []) + keyword_hits.get("recovery_disable", [])),
        "url_or_onion_indicators": keyword_hits.get("onion_or_wallet", []),
        "config_like_strings": [],
    }
    return string_features, matched_features


def _calculate_static_score(pe_features: dict, import_features: dict, string_features: dict, matched_features: list[str], config) -> tuple[float, list[dict]]:
    pe_score = 0.0
    import_score = 0.0
    string_score = 0.0
    breakdown: list[dict] = []

    def add(feature: str, weight: float, score: float, reason: str, bucket: str) -> None:
        nonlocal pe_score, import_score, string_score
        breakdown.append({"feature": feature, "weight": weight, "score": score, "reason": reason})
        contribution = weight * score
        if bucket == "pe":
            pe_score += contribution
        elif bucket == "import":
            import_score += contribution
        else:
            string_score += contribution

    if pe_features["packed_or_obfuscated"]:
        add("packed_binary", 0.15, 1.0, "Multiple high-entropy sections suggest packing or obfuscation.", "pe")
    if pe_features["suspicious_timestamp"]:
        add("suspicious_timestamp", 0.05, 1.0, "PE timestamp is zeroed or suspicious.", "pe")
    if import_features["crypto_api_count"] > 0:
        add("imports_crypto_api", 0.20, min(1.0, import_features["crypto_api_count"] / 4), "Crypto-related imports were found.", "import")
    if import_features["shadowcopy_or_recovery_api_present"]:
        add("imports_shadowcopy_or_recovery_api", 0.20, 1.0, "Recovery-related imports were found.", "import")
    if "imports_filesystem_api_cluster" in matched_features:
        add("imports_filesystem_api_cluster", 0.10, 1.0, "Filesystem-oriented imports suggest bulk file interaction capability.", "import")
    if "contains_ransom_note_keyword" in matched_features:
        add("contains_ransom_note_keyword", 0.35, 1.0, "Strings contain ransom-note-related keywords.", "string")
    if "contains_backup_delete_command" in matched_features:
        add("contains_backup_delete_command", 0.25, 1.0, "Strings contain backup deletion commands.", "string")
    if "contains_recovery_disable_command" in matched_features:
        add("contains_recovery_disable_command", 0.20, 1.0, "Strings contain recovery-disabling commands.", "string")
    if "contains_extension_change_keyword" in matched_features:
        add("contains_extension_change_keyword", 0.15, 1.0, "Strings suggest encrypted extension changes.", "string")
    if "contains_onion_or_wallet_indicator" in matched_features:
        add("contains_onion_or_wallet_indicator", 0.15, 1.0, "Strings contain onion or wallet indicators.", "string")

    weights = config.score_weights
    final_score = (
        min(1.0, pe_score) * weights.get("pe_score", 0.3)
        + min(1.0, import_score) * weights.get("import_score", 0.3)
        + min(1.0, string_score) * weights.get("string_score", 0.4)
    )
    return round(min(1.0, final_score), 3), breakdown


def run_static_analysis(context: AnalysisContext, bundle: RuntimeConfigBundle) -> AnalysisContext:
    result = context.static_analysis
    result.executed = True
    result.status = ModuleStatus.OK.value
    result.tools_used = []
    sample_path = Path(context.sample.file_path)
    config = bundle.static_analysis

    try:
        pe = pefile.PE(str(sample_path), fast_load=False)
        result.tools_used.append("pefile")
        pe_features, _ = _section_features(pe, config.entropy_threshold)
        import_features, import_matches = _import_features(pe)
        result.pe_features = pe_features
        result.import_features = import_features
    except Exception as exc:
        result.status = ModuleStatus.ERROR.value
        result.error = f"STATIC_PE_PARSE_FAILURE: {exc}"
        result.summary = "PE parsing failed during static analysis."
        return context

    keyword_config = DEFAULT_KEYWORDS.copy()
    keyword_config.update(config.string_keyword_sets or {})

    try:
        strings_output = _extract_strings(sample_path)
        result.tools_used.append("strings")
        keyword_hits = _match_keywords(strings_output, keyword_config)
    except Exception as exc:
        result.status = ModuleStatus.PARTIAL.value
        result.error = f"STATIC_STRINGS_FAILURE: {exc}"
        keyword_hits = {key: [] for key in keyword_config}

    string_features, string_matches = _normalize_string_features(keyword_hits)
    result.string_features = string_features

    matched_features = sorted(set(import_matches + string_matches + (["packed_binary"] if result.pe_features.get("packed_or_obfuscated") else [])))
    result.matched_features = matched_features
    result.risk_score, result.score_breakdown = _calculate_static_score(
        result.pe_features,
        result.import_features,
        result.string_features,
        result.matched_features,
        config,
    )

    if result.risk_score >= config.high_score_threshold:
        band = "high"
    elif result.risk_score >= config.medium_score_threshold:
        band = "medium"
    else:
        band = "low"
    result.summary = f"Static analysis completed with {band} risk."

    if config.enable_v2_output:
        try:
            v2_result = extract_pefile_v2(sample_path, config)
            result.v2 = v2_result.to_dict()
        except Exception as exc:
            if result.error:
                result.error = f"{result.error}; STATIC_V2_FAILURE: {exc}"
            else:
                result.error = f"STATIC_V2_FAILURE: {exc}"
            if result.status == ModuleStatus.OK.value:
                result.status = ModuleStatus.PARTIAL.value

    return context
