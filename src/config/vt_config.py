from dataclasses import dataclass, field


@dataclass
class VTConfig:
    enabled: bool = True
    api_key: str = ""
    api_key_file: str = ""
    query_hash_priority: list[str] = field(default_factory=lambda: ["sha256", "sha1", "md5"])
    timeout_sec: int = 20
    retry_enabled: bool = True
    retry_count: int = 1
    rate_limit_sleep_sec: int = 15

