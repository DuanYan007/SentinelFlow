from datetime import datetime


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def timestamp_slug(iso_timestamp: str) -> str:
    return (
        iso_timestamp.replace("-", "")
        .replace(":", "")
        .replace("+", "")
        .replace("T", "T")
    )


def duration_seconds(start_iso: str, end_iso: str) -> float:
    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)
    return round((end - start).total_seconds(), 3)

