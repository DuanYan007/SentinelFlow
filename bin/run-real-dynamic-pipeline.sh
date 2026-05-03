#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ $# -lt 2 ]]; then
  echo "usage: bin/run-real-dynamic-pipeline.sh <sample_path> <sample_sha256> [--execute]" >&2
  exit 2
fi

SAMPLE_PATH="$1"
SAMPLE_SHA256="$2"
EXECUTE_FLAG="${3:-}"
CONFIG_DIR="${PIPELINE_CONFIG_DIR:-configs/replay-validation}"

CLI_CMD=run-real-dynamic-pipeline
if [[ "${PIPELINE_COLLECT_MODE:-}" == "1" ]]; then
  CLI_CMD=collect-real-dynamic
fi

CMD=(
  .venv/bin/python
  -m
  cli
  "$CLI_CMD"
  --sample "$SAMPLE_PATH"
  --sample-sha256 "$SAMPLE_SHA256"
  --config-dir "$CONFIG_DIR"
)

if [[ "$EXECUTE_FLAG" == "--execute" ]]; then
  CMD+=(--execute)
fi

PYTHONPATH=src "${CMD[@]}"
