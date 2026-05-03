@echo off
setlocal

set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "TOOLS_DIR=%~dp0"

if not exist "%POWERSHELL_EXE%" (
  echo ERROR powershell.exe not found
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%TOOLS_DIR%prepare_workspace.ps1"
exit /b %ERRORLEVEL%
