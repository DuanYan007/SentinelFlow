#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VM_NAME="${VM_NAME:-windows-lab}"
VM_USERNAME="${VM_USERNAME:-collector}"
VM_PASSWORD="${VM_PASSWORD:-}"
GUEST_TOOLS_DIR="${GUEST_TOOLS_DIR:-C:\Tools}"

if [[ -z "$VM_PASSWORD" ]]; then
  echo "VM_PASSWORD is required" >&2
  exit 2
fi

copy_file() {
  local src="$1"
  local dst="$2"
  VBoxManage guestcontrol "$VM_NAME" copyto "$src" "$dst" \
    --username "$VM_USERNAME" \
    --password "$VM_PASSWORD"
}

copy_file "${ROOT_DIR}/guest-tools/virtualbox/start_capture.bat" "${GUEST_TOOLS_DIR}\start_capture.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/stop_capture.bat" "${GUEST_TOOLS_DIR}\stop_capture.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/export_logs.bat" "${GUEST_TOOLS_DIR}\export_logs.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/export_logs.ps1" "${GUEST_TOOLS_DIR}\export_logs.ps1"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/export_minimal.bat" "${GUEST_TOOLS_DIR}\export_minimal.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/prepare_workspace.bat" "${GUEST_TOOLS_DIR}\prepare_workspace.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/prepare_workspace.ps1" "${GUEST_TOOLS_DIR}\prepare_workspace.ps1"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/harden_phase1.bat" "${GUEST_TOOLS_DIR}\harden_phase1.bat"
copy_file "${ROOT_DIR}/guest-tools/virtualbox/harden_phase1.ps1" "${GUEST_TOOLS_DIR}\harden_phase1.ps1"

echo "OK guest tool scripts copied to ${GUEST_TOOLS_DIR}"
