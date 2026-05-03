#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VM_NAME="${VM_NAME:-windows-lab}"
VM_USERNAME="${VM_USERNAME:-analyst}"
VM_PASSWORD="${VM_PASSWORD:-}"
GUEST_TOOLS_DIR="${GUEST_TOOLS_DIR:-C:\Tools}"

if [[ -z "$VM_PASSWORD" ]]; then
  echo "VM_PASSWORD is required" >&2
  exit 2
fi

VBoxManage guestcontrol "$VM_NAME" run \
  --exe "C:\Windows\System32\cmd.exe" \
  --username "$VM_USERNAME" \
  --password "$VM_PASSWORD" \
  -- cmd.exe /c "if exist ${GUEST_TOOLS_DIR}\Procmon\Procmon64.exe (echo PROCMon64_OK) else if exist ${GUEST_TOOLS_DIR}\Procmon\Procmon.exe (echo PROCMon_OK) else (echo PROCMON_MISSING & exit /b 1)"
