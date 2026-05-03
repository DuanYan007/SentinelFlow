param(
  [string]$CollectorUsername = "collector",
  [string]$CollectorPassword = "7566",
  [string]$ToolsDir = "C:\Tools",
  [string]$RunsDir = "C:\ProgramData\SentinelFlow\Runs",
  [string]$SamplesDir = "C:\Samples",
  [string]$AnalystUsername = "analyst"
)

$ErrorActionPreference = "Stop"

function Ensure-LocalUser {
  param(
    [string]$Username,
    [string]$Password
  )

  $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $Username -Password $secure -FullName "SentinelFlow Collector" -PasswordNeverExpires | Out-Null
  } else {
    net user $Username $Password | Out-Null
  }
}

function Reset-DirectoryAcl {
  param(
    [string]$Path
  )

  New-Item -ItemType Directory -Path $Path -Force | Out-Null
  & icacls $Path /inheritance:r | Out-Null
}

Ensure-LocalUser -Username $CollectorUsername -Password $CollectorPassword

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
New-Item -ItemType Directory -Path $RunsDir -Force | Out-Null
New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null

Reset-DirectoryAcl -Path $ToolsDir
& icacls $ToolsDir /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "${CollectorUsername}:(OI)(CI)M" "${AnalystUsername}:(OI)(CI)RX" | Out-Null

Reset-DirectoryAcl -Path $RunsDir
& icacls $RunsDir /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "${CollectorUsername}:(OI)(CI)M" | Out-Null
& icacls $RunsDir /deny "${AnalystUsername}:(OI)(CI)W" | Out-Null

& icacls $SamplesDir /inheritance:e | Out-Null

$summary = [PSCustomObject]@{
  collector_username = $CollectorUsername
  tools_dir = $ToolsDir
  runs_dir = $RunsDir
  samples_dir = $SamplesDir
  analyst_username = $AnalystUsername
}

$summary | ConvertTo-Json -Depth 4
