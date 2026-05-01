from dataclasses import dataclass


@dataclass
class SampleInfo:
    file_name: str = ""
    file_path: str = ""
    file_size: int = 0
    file_type: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    submitted_at: str = ""

