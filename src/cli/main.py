from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.constants import DEFAULT_CONFIGS_DIR
from config.loader import load_runtime_config
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


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate-result":
        return _run_validate_result(args.result)
    if args.command == "single":
        return _run_single(args.sample, args.config_dir, args.output_dir)
    parser.error(f"unknown command: {args.command}")
    return 2
