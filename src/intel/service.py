import json
from pathlib import Path
from urllib import error, parse, request

from config.loader import RuntimeConfigBundle
from core.enums import ModuleStatus
from models.analysis_context import AnalysisContext


def _load_api_key(bundle: RuntimeConfigBundle) -> str:
    if bundle.virustotal.api_key:
        return bundle.virustotal.api_key.strip()
    if bundle.virustotal.api_key_file:
        path = Path(bundle.virustotal.api_key_file)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    return ""


def _signal_from_counts(malicious_count: int) -> str:
    if malicious_count >= 10:
        return "high"
    if malicious_count >= 3:
        return "medium"
    return "low"


def _normalize_vt_payload(payload: dict, context: AnalysisContext) -> None:
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    context.threat_intel.matched = True
    context.threat_intel.malicious_count = int(stats.get("malicious", 0))
    context.threat_intel.suspicious_count = int(stats.get("suspicious", 0))
    context.threat_intel.harmless_count = int(stats.get("harmless", 0))
    context.threat_intel.undetected_count = int(stats.get("undetected", 0))
    context.threat_intel.reputation = int(payload.get("data", {}).get("attributes", {}).get("reputation", 0))
    tags = payload.get("data", {}).get("attributes", {}).get("tags", []) or []
    context.threat_intel.label = "ransomware" if "ransomware" in tags else "malware" if tags else "unknown"
    context.threat_intel.permalink = (
        f"https://www.virustotal.com/gui/file/{context.sample.sha256}"
        if context.sample.sha256
        else ""
    )
    context.threat_intel.raw_summary = "VT hit with malicious statistics"
    context.threat_intel.vt_signal = _signal_from_counts(context.threat_intel.malicious_count)
    context.threat_intel.status = ModuleStatus.OK.value
    context.threat_intel.error = None


def _query_vt(sha256_value: str, api_key: str, timeout_sec: int) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{parse.quote(sha256_value)}"
    req = request.Request(url, headers={"x-apikey": api_key})
    with request.urlopen(req, timeout=timeout_sec) as response:
        return json.loads(response.read().decode("utf-8"))


def run_threat_intel(context: AnalysisContext, bundle: RuntimeConfigBundle) -> AnalysisContext:
    context.threat_intel.query_hash_type = "sha256"
    context.threat_intel.query_hash_value = context.sample.sha256

    if not bundle.virustotal.enabled:
        context.threat_intel.status = ModuleStatus.SKIPPED.value
        context.threat_intel.raw_summary = "VT disabled by config"
        return context

    api_key = _load_api_key(bundle)
    if not api_key:
        context.threat_intel.status = ModuleStatus.ERROR.value
        context.threat_intel.error = "VT API key is missing"
        context.threat_intel.raw_summary = "VT unavailable: missing API key"
        return context

    try:
        payload = _query_vt(context.sample.sha256, api_key, bundle.virustotal.timeout_sec)
    except error.HTTPError as exc:
        if exc.code == 404:
            context.threat_intel.status = ModuleStatus.OK.value
            context.threat_intel.matched = False
            context.threat_intel.vt_signal = "low"
            context.threat_intel.raw_summary = "VT no hit"
            return context
        context.threat_intel.status = ModuleStatus.ERROR.value
        context.threat_intel.error = f"VT HTTP error: {exc.code}"
        context.threat_intel.raw_summary = "VT query failed"
        return context
    except error.URLError as exc:
        context.threat_intel.status = ModuleStatus.ERROR.value
        context.threat_intel.error = f"VT network failure: {exc.reason}"
        context.threat_intel.raw_summary = "VT query failed"
        return context
    except TimeoutError:
        context.threat_intel.status = ModuleStatus.ERROR.value
        context.threat_intel.error = "VT timeout"
        context.threat_intel.raw_summary = "VT query timed out"
        return context

    _normalize_vt_payload(payload, context)
    return context

