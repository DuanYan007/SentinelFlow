@echo off
setlocal

set "TOOLS_DIR=%~dp0"
set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon64.exe"

if not exist "%PROCMON_EXE%" set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon.exe"

if not exist "%PROCMON_EXE%" (
  echo ERROR Procmon executable not found under %TOOLS_DIR%Procmon
  exit /b 1
)

"%PROCMON_EXE%" /Terminate /AcceptEula /Quiet
if errorlevel 1 (
  echo ERROR failed to stop Procmon capture
  exit /b 1
)

echo OK stopped procmon capture
exit /b 0
