from dataclasses import dataclass

from core.constants import DEFAULT_LOGS_DIR


@dataclass
class LoggingConfig:
    log_level: str = "INFO"
    structured_logging: bool = True
    log_dir: str = DEFAULT_LOGS_DIR
    retain_debug_logs: bool = False
    separate_agent_log: bool = True

