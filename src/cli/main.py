from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.constants import DEFAULT_CONFIGS_DIR
from batch import run_dynamic_experiment
from config.loader import load_runtime_config
from dynamic_collection import (
    build_unified_raw_log,
    parse_procmon_json,
    parse_sysmon_json,
    plan_or_run_real_dynamic_collection,
    prepare_real_dynamic_artifacts,
)
from dynamic_analysis import build_dynamic_replay_artifact
from recorder.validator import validate_result_dict
from recorder.result_writer import write_single_result
from workflow_skeleton import single_sample_workflow


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ransom-lab", description="Phase-1 ransomware analysis CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-result", help="Validate a result JSON structure")
    validate_parser.add_argument("--result", required=True, help="Path to a result JSON file")

    single_parser = subparsers.add_parser("single", help="Run phase-1 workflow for one sample")
    single_parser.add_argument("--sample", required=True, help="Path to a sample file")
    single_parser.add_argument("--config-dir", default=DEFAULT_CONFIGS_DIR, help="Path to config directory")
    single_parser.add_argument("--output-dir", help="Override result output directory")

    dynamic_parser = subparsers.add_parser("dynamic-experiment", help="Run dynamic-only replay analysis for artifacts")
    dynamic_parser.add_argument("--input-dir", required=True, help="Directory of dynamic replay JSON artifacts")
    dynamic_parser.add_argument("--config-dir", default=DEFAULT_CONFIGS_DIR, help="Path to config directory")
    dynamic_parser.add_argument("--output-dir", help="Override result output directory")

    build_parser = subparsers.add_parser(
        "build-dynamic-artifact",
        help="Convert a raw dynamic log JSON into the standard replay artifact format",
    )
    build_parser.add_argument("--raw-log", required=True, help="Path to the raw dynamic log JSON")
    build_parser.add_argument("--output-dir", default="staging/dynamic-replay", help="Directory for replay artifacts")

    import_sysmon_parser = subparsers.add_parser(
        "import-sysmon-log",
        help="Import a Sysmon JSON export into the unified raw dynamic log format",
    )
    import_sysmon_parser.add_argument("--sysmon-log", required=True, help="Path to the Sysmon JSON export")
    import_sysmon_parser.add_argument("--output", required=True, help="Path to the unified raw dynamic log JSON")

    import_procmon_parser = subparsers.add_parser(
        "import-procmon-log",
        help="Import a Procmon JSON export into the unified raw dynamic log format",
    )
    import_procmon_parser.add_argument("--procmon-log", required=True, help="Path to the Procmon JSON export")
    import_procmon_parser.add_argument("--output", required=True, help="Path to the unified raw dynamic log JSON")

    import_real_run_parser = subparsers.add_parser(
        "import-real-run",
        help="Import Sysmon and Procmon JSON exports and merge them into one unified raw dynamic log",
    )
    import_real_run_parser.add_argument("--sysmon-log", required=True, help="Path to the Sysmon JSON export")
    import_real_run_parser.add_argument("--procmon-log", required=True, help="Path to the Procmon JSON export")
    import_real_run_parser.add_argument("--output", required=True, help="Path to the merged unified raw dynamic log JSON")

    orchestrate_parser = subparsers.add_parser(
        "run-real-dynamic-pipeline",
        help="Plan or run host-side orchestration steps for a real Windows VM dynamic collection",
    )
    orchestrate_parser.add_argument("--sample", required=True, help="Path to the PE sample file")
    orchestrate_parser.add_argument("--sample-sha256", required=True, help="Sample sha256 used for run directory naming")
    orchestrate_parser.add_argument("--config-dir", default=DEFAULT_CONFIGS_DIR, help="Path to config directory")
    orchestrate_parser.add_argument("--execute", action="store_true", help="Actually run configured host-side commands")

    collect_parser = subparsers.add_parser(
        "collect-real-dynamic",
        help="Run the host-side real dynamic pipeline and immediately normalize collected logs into a replay artifact",
    )
    collect_parser.add_argument("--sample", required=True, help="Path to the PE sample file")
    collect_parser.add_argument("--sample-sha256", required=True, help="Sample sha256 used for real-run directory naming")
    collect_parser.add_argument("--config-dir", default=DEFAULT_CONFIGS_DIR, help="Path to config directory")
    collect_parser.add_argument("--execute", action="store_true", help="Actually run the host-side VM commands")

    return parser


def _run_validate_result(result_path: str) -> int:
    path = Path(result_path)
    if not path.exists():
        print(f"ERROR result file not found: {path}")
        return 2
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR invalid JSON: {exc}")
        return 2

    validation = validate_result_dict(data)
    if validation.valid:
        print(f"OK {path}")
        if validation.warnings:
            for warning in validation.warnings:
                print(f"WARN {warning}")
        return 0

    print(f"INVALID {path}")
    for error in validation.errors:
        print(f"ERROR {error}")
    for warning in validation.warnings:
        print(f"WARN {warning}")
    return 1


def _run_single(sample_path: str, config_dir: str, output_dir: str | None) -> int:
    path = Path(sample_path)
    if not path.exists():
        print(f"ERROR sample file not found: {path}")
        return 2
    if not path.is_file():
        print(f"ERROR sample path is not a file: {path}")
        return 2

    runtime_config = load_runtime_config(config_dir)
    context = single_sample_workflow(str(path), runtime_config)
    result_dir = output_dir or runtime_config.phase1.results_dir
    result_path = write_single_result(context, result_dir)
    validation = validate_result_dict(json.loads(Path(result_path).read_text(encoding="utf-8")))
    if not validation.valid:
        print(f"INVALID {result_path}")
        for error in validation.errors:
            print(f"ERROR {error}")
        for warning in validation.warnings:
            print(f"WARN {warning}")
        return 1
    print(f"OK {result_path}")
    print(f"VERDICT {context.verdict.final_label}")
    print(f"STATUS {context.workflow_status.status}")
    if context.static_analysis.v2:
        v2 = context.static_analysis.v2
        print(f"STATIC_V2 {v2.get('risk_score')}")
    return 0


def _run_dynamic_experiment(input_dir: str, config_dir: str, output_dir: str | None) -> int:
    path = Path(input_dir)
    if not path.exists():
        print(f"ERROR input directory not found: {path}")
        return 2
    if not path.is_dir():
        print(f"ERROR input path is not a directory: {path}")
        return 2

    runtime_config = load_runtime_config(config_dir)
    result_dir = output_dir or runtime_config.phase1.results_dir
    summary = run_dynamic_experiment(runtime_config, str(path), result_dir)
    print(f"OK {summary['batch_id']}")
    print(f"ARTIFACTS {summary['input_stats']['processed_artifacts']}")
    print(f"DYNAMIC_OK {summary['dynamic_stats']['status_counts'].get('ok', 0)}")
    print(f"DYNAMIC_MEAN_SCORE {summary['dynamic_stats']['mean_risk_score']}")
    return 0


def _run_build_dynamic_artifact(raw_log: str, output_dir: str) -> int:
    path = Path(raw_log)
    if not path.exists():
        print(f"ERROR raw log file not found: {path}")
        return 2
    if not path.is_file():
        print(f"ERROR raw log path is not a file: {path}")
        return 2

    result = build_dynamic_replay_artifact(str(path), output_dir)
    print(f"OK {result.output_path}")
    print(f"SCHEMA {result.schema_version}")
    print(f"PROCESS_EVENTS {result.process_event_count}")
    print(f"FILE_EVENTS {result.file_event_count}")
    for warning in result.warnings:
        print(f"WARN {warning}")
    return 0


def _run_import_sysmon_log(sysmon_log: str, output_path: str) -> int:
    path = Path(sysmon_log)
    if not path.exists():
        print(f"ERROR sysmon log file not found: {path}")
        return 2
    data = parse_sysmon_json(str(path))
    unified_path = build_unified_raw_log(
        sample_sha256=data.get("sample_sha256", ""),
        sysmon_data=data,
        output_path=output_path,
    )
    print(f"OK {unified_path}")
    print(f"PROCESS_EVENTS {len(data.get('process_events', []))}")
    print(f"FILE_EVENTS {len(data.get('file_events', []))}")
    return 0


def _run_import_procmon_log(procmon_log: str, output_path: str) -> int:
    path = Path(procmon_log)
    if not path.exists():
        print(f"ERROR procmon log file not found: {path}")
        return 2
    data = parse_procmon_json(str(path))
    unified_path = build_unified_raw_log(
        sample_sha256=data.get("sample_sha256", ""),
        procmon_data=data,
        output_path=output_path,
    )
    print(f"OK {unified_path}")
    print(f"PROCESS_EVENTS {len(data.get('process_events', []))}")
    print(f"FILE_EVENTS {len(data.get('file_events', []))}")
    return 0


def _run_import_real_run(sysmon_log: str, procmon_log: str, output_path: str) -> int:
    sysmon_path = Path(sysmon_log)
    procmon_path = Path(procmon_log)
    if not sysmon_path.exists():
        print(f"ERROR sysmon log file not found: {sysmon_path}")
        return 2
    if not procmon_path.exists():
        print(f"ERROR procmon log file not found: {procmon_path}")
        return 2

    sysmon_data = parse_sysmon_json(str(sysmon_path))
    procmon_data = parse_procmon_json(str(procmon_path))
    sample_sha256 = sysmon_data.get("sample_sha256") or procmon_data.get("sample_sha256") or ""
    unified_path = build_unified_raw_log(
        sample_sha256=sample_sha256,
        sysmon_data=sysmon_data,
        procmon_data=procmon_data,
        output_path=output_path,
    )
    print(f"OK {unified_path}")
    print(f"SOURCES 2")
    print(
        f"PROCESS_EVENTS {len(sysmon_data.get('process_events', [])) + len(procmon_data.get('process_events', []))}"
    )
    print(f"FILE_EVENTS {len(sysmon_data.get('file_events', [])) + len(procmon_data.get('file_events', []))}")
    return 0


def _run_real_dynamic_pipeline(sample_path: str, sample_sha256: str, config_dir: str, execute: bool) -> int:
    path = Path(sample_path)
    if not path.exists():
        print(f"ERROR sample file not found: {path}")
        return 2

    runtime_config = load_runtime_config(config_dir)
    result = plan_or_run_real_dynamic_collection(
        sample_path=str(path),
        sample_sha256=sample_sha256,
        bundle=runtime_config,
        dry_run=not execute,
    )
    print(f"OK {result.run_dir}")
    for step in result.steps:
        if step.command:
            print(f"STEP {step.step} {step.status}")
            print(f"COMMAND {step.command}")
        else:
            print(f"STEP {step.step} skipped")
        if step.output:
            print(f"OUTPUT {step.output}")
        if step.status == "error":
            return 1
    return 0


def _run_collect_real_dynamic(sample_path: str, sample_sha256: str, config_dir: str, execute: bool) -> int:
    pipeline_rc = _run_real_dynamic_pipeline(sample_path, sample_sha256, config_dir, execute)
    if pipeline_rc != 0:
        return pipeline_rc
    if not execute:
        print("INFO dry-run completed; skipping artifact preparation")
        return 0

    runtime_config = load_runtime_config(config_dir)
    from models.analysis_context import create_empty_analysis_context

    context = create_empty_analysis_context(sample_path, runtime_config.phase1.phase_name)
    context.sample.sha256 = sample_sha256
    result = prepare_real_dynamic_artifacts(context, runtime_config)
    if result.status != "ok":
        print(f"ERROR {result.summary}")
        return 1
    print(f"RAW_LOG {result.raw_log_path}")
    print(f"REPLAY_ARTIFACT {result.replay_artifact_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate-result":
        return _run_validate_result(args.result)
    if args.command == "single":
        return _run_single(args.sample, args.config_dir, args.output_dir)
    if args.command == "dynamic-experiment":
        return _run_dynamic_experiment(args.input_dir, args.config_dir, args.output_dir)
    if args.command == "build-dynamic-artifact":
        return _run_build_dynamic_artifact(args.raw_log, args.output_dir)
    if args.command == "import-sysmon-log":
        return _run_import_sysmon_log(args.sysmon_log, args.output)
    if args.command == "import-procmon-log":
        return _run_import_procmon_log(args.procmon_log, args.output)
    if args.command == "import-real-run":
        return _run_import_real_run(args.sysmon_log, args.procmon_log, args.output)
    if args.command == "run-real-dynamic-pipeline":
        return _run_real_dynamic_pipeline(args.sample, args.sample_sha256, args.config_dir, args.execute)
    if args.command == "collect-real-dynamic":
        return _run_collect_real_dynamic(args.sample, args.sample_sha256, args.config_dir, args.execute)
    parser.error(f"unknown command: {args.command}")
    return 2
