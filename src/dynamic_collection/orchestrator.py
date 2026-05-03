from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from config.loader import RuntimeConfigBundle


@dataclass
class OrchestrationStepResult:
    step: str
    status: str
    command: str
    output: str = ""


@dataclass
class RealRunOrchestrationResult:
    sample_path: str
    sample_sha256: str
    run_dir: str
    steps: list[OrchestrationStepResult]


def _render_command(template: str, replacements: dict[str, str]) -> str:
    command = template
    for key, value in replacements.items():
        command = command.replace(f"{{{key}}}", str(value))
    return command.strip()


def _run_step(step: str, command_template: str, replacements: dict[str, str], dry_run: bool) -> OrchestrationStepResult:
    command = _render_command(command_template, replacements)
    if not command:
        return OrchestrationStepResult(step=step, status="skipped", command="")
    if dry_run:
        return OrchestrationStepResult(step=step, status="planned", command=command)

    completed = subprocess.run(
        shlex.split(command),
        capture_output=True,
        text=True,
        check=False,
    )
    output = "\n".join(part for part in [completed.stdout.strip(), completed.stderr.strip()] if part).strip()
    status = "ok" if completed.returncode == 0 else "error"
    return OrchestrationStepResult(step=step, status=status, command=command, output=output)


def _validate_execution_guard(bundle: RuntimeConfigBundle, dry_run: bool) -> None:
    if dry_run:
        return
    if not bundle.dynamic_analysis.enable_real_vm_execution:
        raise ValueError("Real VM execution is disabled by config. Set enable_real_vm_execution=true explicitly.")
    if not bundle.dynamic_analysis.allow_sample_execution:
        raise ValueError("Sample execution is blocked by config. Set allow_sample_execution=true explicitly.")
    if bundle.dynamic_analysis.vm_platform != "virtualbox":
        raise ValueError("Executable orchestration currently only supports vm_platform=virtualbox.")


def plan_or_run_real_dynamic_collection(
    *,
    sample_path: str,
    sample_sha256: str,
    bundle: RuntimeConfigBundle,
    dry_run: bool = True,
) -> RealRunOrchestrationResult:
    _validate_execution_guard(bundle, dry_run)
    run_dir = Path(bundle.dynamic_analysis.real_runs_dir) / sample_sha256
    run_dir.mkdir(parents=True, exist_ok=True)
    sample_name = Path(sample_path).name
    guest_sample_path = f"{bundle.dynamic_analysis.vm_guest_sample_dir}\\{sample_name}"
    replacements = {
        "sample_path": sample_path,
        "sample_name": sample_name,
        "sample_sha256": sample_sha256,
        "run_dir": str(run_dir),
        "snapshot_name": bundle.dynamic_analysis.snapshot_name,
        "vm_name": bundle.dynamic_analysis.vm_name,
        "vm_guest_ip": bundle.dynamic_analysis.vm_guest_ip,
        "vm_username": bundle.dynamic_analysis.vm_username,
        "vm_password": bundle.dynamic_analysis.vm_password,
        "vm_guest_sample_dir": bundle.dynamic_analysis.vm_guest_sample_dir,
        "vm_guest_logs_dir": bundle.dynamic_analysis.vm_guest_logs_dir,
        "vm_guest_tools_dir": bundle.dynamic_analysis.vm_guest_tools_dir,
        "vm_ready_check_command": bundle.dynamic_analysis.vm_ready_check_command,
        "guest_sample_path": guest_sample_path,
        "observation_window_sec": str(bundle.dynamic_analysis.observation_window_sec),
    }
    steps = [
        _run_step("restore_snapshot", bundle.dynamic_analysis.vm_snapshot_restore_command, replacements, dry_run),
        _run_step("start_vm", bundle.dynamic_analysis.vm_start_command, replacements, dry_run),
        _run_step("wait_guest_ready", bundle.dynamic_analysis.vm_ready_check_command, replacements, dry_run),
        _run_step("copy_sample", bundle.dynamic_analysis.vm_copy_sample_command, replacements, dry_run),
        _run_step("start_capture", bundle.dynamic_analysis.vm_start_capture_command, replacements, dry_run),
        _run_step("execute_sample", bundle.dynamic_analysis.vm_execute_sample_command, replacements, dry_run),
        _run_step("stop_capture", bundle.dynamic_analysis.vm_stop_capture_command, replacements, dry_run),
        _run_step("export_logs", bundle.dynamic_analysis.vm_export_logs_command, replacements, dry_run),
        _run_step("collect_logs", bundle.dynamic_analysis.vm_collect_logs_command, replacements, dry_run),
    ]
    return RealRunOrchestrationResult(
        sample_path=sample_path,
        sample_sha256=sample_sha256,
        run_dir=str(run_dir),
        steps=steps,
    )
