from dataclasses import asdict, dataclass
from pathlib import Path

from .logging_config import LoggingConfig
from .phase1_config import Phase1Config
from .static_config import StaticConfig
from .vt_config import VTConfig

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency in round 1
    yaml = None


@dataclass
class RuntimeConfigBundle:
    phase1: Phase1Config
    virustotal: VTConfig
    static_analysis: StaticConfig
    logging: LoggingConfig

    def to_dict(self) -> dict:
        return asdict(self)


def _load_yaml_overrides(path: Path) -> dict:
    if not path.exists() or yaml is None:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        return {}
    return data


def _apply_overrides(config_obj, overrides: dict):
    values = asdict(config_obj)
    values.update(overrides)
    return type(config_obj)(**values)


def load_phase1_config(config_dir: str) -> Phase1Config:
    return _apply_overrides(Phase1Config(), _load_yaml_overrides(Path(config_dir) / "phase1.yaml"))


def load_vt_config(config_dir: str) -> VTConfig:
    return _apply_overrides(VTConfig(), _load_yaml_overrides(Path(config_dir) / "virustotal.yaml"))


def load_static_config(config_dir: str) -> StaticConfig:
    return _apply_overrides(StaticConfig(), _load_yaml_overrides(Path(config_dir) / "static-analysis.yaml"))


def load_logging_config(config_dir: str) -> LoggingConfig:
    return _apply_overrides(LoggingConfig(), _load_yaml_overrides(Path(config_dir) / "logging.yaml"))


def load_runtime_config(config_dir: str) -> RuntimeConfigBundle:
    return RuntimeConfigBundle(
        phase1=load_phase1_config(config_dir),
        virustotal=load_vt_config(config_dir),
        static_analysis=load_static_config(config_dir),
        logging=load_logging_config(config_dir),
    )
