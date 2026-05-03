@echo off
setlocal

if "%~1"=="" (
  echo usage: export_logs.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

if "%~2"=="" (
  echo usage: export_logs.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

set "LOGS_DIR=%~1"
set "SAMPLE_SHA256=%~2"
set "TOOLS_DIR=%~dp0"
set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%POWERSHELL_EXE%" (
  echo ERROR powershell.exe not found
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%export_logs.ps1" "%LOGS_DIR%" "%SAMPLE_SHA256%"
exit /b %ERRORLEVEL%
