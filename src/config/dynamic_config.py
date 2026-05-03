from dataclasses import dataclass


@dataclass
class DynamicConfig:
    enabled: bool = False
    environment_type: str = "windows_vm"
    adapter_name: str = "event_log_adapter"
    snapshot_name: str = "clean-baseline"
    network_mode: str = "host_only"
    runner_command: str = ""
    event_log_path: str = ""
    replay_artifact_dir: str = "staging/dynamic-replay"
    real_runs_dir: str = "data"
    fallback_adapters: list[str] | None = None
    allow_agent_override: bool = True
    allow_sample_execution: bool = False
    enable_real_vm_execution: bool = False
    vm_platform: str = "manual"
    vm_name: str = ""
    vm_guest_ip: str = ""
    vm_username: str = ""
    vm_password: str = ""
    vm_control_username: str = ""
    vm_control_password: str = ""
    vm_sample_username: str = ""
    vm_sample_password: str = ""
    vm_guest_sample_dir: str = "C:\\Samples"
    vm_guest_logs_dir: str = "C:\\AnalysisLogs"
    vm_guest_tools_dir: str = "C:\\Tools"
    vm_ready_check_command: str = ""
    vm_snapshot_restore_command: str = ""
    vm_start_command: str = ""
    vm_copy_sample_command: str = ""
    vm_start_capture_command: str = ""
    vm_execute_sample_command: str = ""
    vm_stop_capture_command: str = ""
    vm_export_logs_command: str = ""
    vm_collect_logs_command: str = ""
    observation_window_sec: int = 60
    process_event_enabled: bool = True
    file_event_enabled: bool = True
    bulk_create_threshold: int = 20
    bulk_modify_threshold: int = 20
    bulk_rename_threshold: int = 10
    high_write_density_threshold: str = "medium"
    timeout_sec: int = 90
