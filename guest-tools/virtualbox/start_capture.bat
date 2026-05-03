@echo off
setlocal

if "%~1"=="" (
  echo usage: start_capture.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

if "%~2"=="" (
  echo usage: start_capture.bat ^<logs_dir^> ^<sample_sha256^>
  exit /b 2
)

set "LOGS_DIR=%~1"
set "SAMPLE_SHA256=%~2"
set "RUN_DIR=%LOGS_DIR%\%SAMPLE_SHA256%"
set "TOOLS_DIR=%~dp0"
set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon64.exe"

if not exist "%PROCMON_EXE%" set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon.exe"

if not exist "%PROCMON_EXE%" (
  echo ERROR Procmon executable not found under %TOOLS_DIR%Procmon
  exit /b 1
)

if not exist "%RUN_DIR%" mkdir "%RUN_DIR%"

del /f /q "%RUN_DIR%\procmon.pml" 2>nul
del /f /q "%RUN_DIR%\procmon.csv" 2>nul
del /f /q "%RUN_DIR%\procmon.json" 2>nul

start "" /min "%PROCMON_EXE%" /AcceptEula /Quiet /Minimized /BackingFile "%RUN_DIR%\procmon.pml"
if errorlevel 1 (
  echo ERROR failed to start Procmon capture
  exit /b 1
)

ping -n 3 127.0.0.1 >nul

echo OK started procmon capture into %RUN_DIR%\procmon.pml
exit /b 0
