@echo off
setlocal

set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "TOOLS_DIR=%~dp0"
set "STAGED_PS1=%TEMP%\harden_phase1.ps1"

if not exist "%POWERSHELL_EXE%" (
  echo ERROR powershell.exe not found
  exit /b 1
)

copy /Y "%TOOLS_DIR%harden_phase1.ps1" "%STAGED_PS1%" >nul
if errorlevel 1 (
  echo ERROR failed to stage harden_phase1.ps1 into %TEMP%
  exit /b 1
)

"%POWERSHELL_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%STAGED_PS1%"
set "RC=%ERRORLEVEL%"
del /f /q "%STAGED_PS1%" >nul 2>nul
exit /b %RC%
