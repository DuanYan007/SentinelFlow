param(
  [string]$SampleWorkspace = "C:\Samples",
  [int]$DesktopFileCount = 30,
  [string]$DesktopSubdirName = "SentinelFlowTestData"
)

$ErrorActionPreference = "Stop"

$desktopPath = [Environment]::GetFolderPath("Desktop")
if (-not $desktopPath) {
  throw "Desktop path not found."
}

$targetDesktopDir = Join-Path $desktopPath $DesktopSubdirName
New-Item -ItemType Directory -Path $SampleWorkspace -Force | Out-Null
New-Item -ItemType Directory -Path $targetDesktopDir -Force | Out-Null

$extensions = @(".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png")

for ($i = 1; $i -le $DesktopFileCount; $i++) {
  $ext = $extensions[($i - 1) % $extensions.Count]
  $name = "sentinelflow_test_{0:D3}{1}" -f $i, $ext
  $path = Join-Path $targetDesktopDir $name
  $content = @(
    "SentinelFlow dynamic lab test file"
    "index=$i"
    "extension=$ext"
    "created=$(Get-Date -Format o)"
  ) -join [Environment]::NewLine
  Set-Content -Path $path -Value $content -Encoding UTF8
}

$summary = [PSCustomObject]@{
  sample_workspace = $SampleWorkspace
  desktop_dir = $targetDesktopDir
  desktop_file_count = $DesktopFileCount
  extensions = $extensions
}

$summary | ConvertTo-Json -Depth 4
