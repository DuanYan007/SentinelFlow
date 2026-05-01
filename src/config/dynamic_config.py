from dataclasses import dataclass


@dataclass
class DynamicConfig:
    enabled: bool = False
    environment_type: str = "windows_vm"
    snapshot_name: str = "clean-baseline"
    network_mode: str = "host_only"
    runner_command: str = ""
    event_log_path: str = ""
    observation_window_sec: int = 60
    process_event_enabled: bool = True
    file_event_enabled: bool = True
    bulk_create_threshold: int = 20
    bulk_modify_threshold: int = 20
    bulk_rename_threshold: int = 10
    high_write_density_threshold: str = "medium"
    timeout_sec: int = 90
