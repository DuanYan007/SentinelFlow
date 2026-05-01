from dataclasses import dataclass

from core.constants import (
    DEFAULT_LOGS_DIR,
    DEFAULT_PHASE_NAME,
    DEFAULT_RESULTS_DIR,
    DEFAULT_STAGING_DIR,
)


@dataclass
class Phase1Config:
    phase_name: str = DEFAULT_PHASE_NAME
    default_mode: str = "single"
    observation_window_sec: int = 60
    allow_auto_rerun: bool = True
    max_auto_rerun: int = 1
    enable_batch_dedup: bool = True
    results_dir: str = DEFAULT_RESULTS_DIR
    logs_dir: str = DEFAULT_LOGS_DIR
    staging_dir: str = DEFAULT_STAGING_DIR

