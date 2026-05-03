param(
  [Parameter(Mandatory = $true)]
  [string]$LogsDir,

  [Parameter(Mandatory = $true)]
  [string]$SampleSha256
)

$ErrorActionPreference = "Stop"

function Get-SafeExtension {
  param(
    [string]$Value
  )

  if (-not $Value) {
    return ""
  }

  $match = [regex]::Match($Value, '\.[A-Za-z0-9]{1,16}(?=$|[\s\x22\x27])')
  if ($match.Success) {
    return $match.Value
  }
  return ""
}

$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$procmon64 = Join-Path $toolsDir "Procmon\Procmon64.exe"
$procmon32 = Join-Path $toolsDir "Procmon\Procmon.exe"
$procmonExe = if (Test-Path $procmon64) { $procmon64 } else { $procmon32 }

if (-not (Test-Path $procmonExe)) {
  throw "Procmon executable not found under $toolsDir\Procmon"
}

$runDir = Join-Path $LogsDir $SampleSha256
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$procmonPml = Join-Path $runDir "procmon.pml"
$procmonCsv = Join-Path $runDir "procmon.csv"
$procmonJson = Join-Path $runDir "procmon.json"
$sysmonEvtx = Join-Path $runDir "sysmon.evtx"
$sysmonJson = Join-Path $runDir "sysmon.json"

wevtutil epl "Microsoft-Windows-Sysmon/Operational" "$sysmonEvtx" /ow:true | Out-Null

$sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $dataMap = @{}
  foreach ($item in $xml.Event.EventData.Data) {
    if ($item.Name) {
      $dataMap[$item.Name] = [string]$item.'#text'
    }
  }

  $targetFilename = [string]($dataMap["TargetFilename"])
  $targetExtension = ""
  if ($targetFilename) {
    $targetExtension = Get-SafeExtension $targetFilename
  }

  [PSCustomObject]@{
    event_id             = [int]$_.Id
    utc_time             = [string]($dataMap["UtcTime"])
    image                = [string]($dataMap["Image"])
    process_name         = [string]($dataMap["Image"])
    pid                  = [int]([string]($dataMap["ProcessId"]) -as [int])
    parent_pid           = [int]([string]($dataMap["ParentProcessId"]) -as [int])
    suspicious_spawn     = $false
    target_filename      = $targetFilename
    created_count        = if ($_.Id -eq 11) { 1 } else { 0 }
    modified_count       = 0
    renamed_count        = 0
    high_frequency_write = $false
    target_extensions    = if ($targetExtension) { @($targetExtension) } else { @() }
    command_line         = [string]($dataMap["CommandLine"])
    parent_command_line  = [string]($dataMap["ParentCommandLine"])
  }
}

@{
  sample_sha256 = $SampleSha256
  events = @($sysmonEvents)
} | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $sysmonJson

if (Test-Path $procmonPml) {
  & $procmonExe /OpenLog $procmonPml /SaveApplyFilter /SaveAs $procmonCsv /Quiet /AcceptEula | Out-Null
}

if (Test-Path $procmonCsv) {
  $procmonRows = Import-Csv $procmonCsv | ForEach-Object {
    $pathValue = [string]($_.Path)
    $extension = ""
    if ($pathValue) {
      $extension = Get-SafeExtension $pathValue
    }

    [PSCustomObject]@{
      operation            = [string]($_.Operation)
      process_name         = [string]($_."Process Name")
      pid                  = [int]([string]($_.PID) -as [int])
      parent_pid           = 0
      suspicious_spawn     = $false
      path                 = $pathValue
      high_frequency_write = ([string]($_.Operation) -eq "WriteFile")
      target_extensions    = if ($extension) { @($extension) } else { @() }
    }
  }

  @{
    sample_sha256 = $SampleSha256
    rows = @($procmonRows)
  } | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $procmonJson
}

Write-Host "OK exported logs to $runDir"
