@echo off
setlocal

if "%~1"=="" (
  echo usage: export_minimal.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

if "%~2"=="" (
  echo usage: export_minimal.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

set "LOGS_DIR=%~1"
set "SAMPLE_SHA256=%~2"
set "RUN_DIR=%LOGS_DIR%\%SAMPLE_SHA256%"
set "PROCMON_EXE=C:\Tools\Procmon\Procmon64.exe"

if not exist "%PROCMON_EXE%" set "PROCMON_EXE=C:\Tools\Procmon\Procmon.exe"

if not exist "%RUN_DIR%" (
  echo ERROR run dir not found: %RUN_DIR%
  exit /b 1
)

taskkill /F /IM Procmon64.exe >nul 2>nul
taskkill /F /IM Procmon.exe >nul 2>nul

wevtutil epl "Microsoft-Windows-Sysmon/Operational" "%RUN_DIR%\sysmon.evtx" /ow:true
if errorlevel 1 (
  echo ERROR failed to export sysmon.evtx
  exit /b 1
)

if not exist "%RUN_DIR%\procmon.pml" (
  echo ERROR procmon.pml not found: %RUN_DIR%\procmon.pml
  exit /b 1
)

if not exist "%PROCMON_EXE%" (
  echo ERROR Procmon executable not found under C:\Tools\Procmon
  exit /b 1
)

"%PROCMON_EXE%" /OpenLog "%RUN_DIR%\procmon.pml" /SaveApplyFilter /SaveAs "%RUN_DIR%\procmon.csv" /Quiet /AcceptEula
if errorlevel 1 (
  echo ERROR failed to export procmon.csv
  exit /b 1
)

echo OK minimal export completed for %RUN_DIR%
exit /b 0
