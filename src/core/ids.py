from datetime import datetime, timezone
from uuid import uuid4


def generate_workflow_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"wf-{timestamp}-{uuid4().hex[:8]}"


def generate_batch_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"batch-{timestamp}-{uuid4().hex[:6]}"

