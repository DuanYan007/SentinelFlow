@echo off
setlocal EnableDelayedExpansion

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
set "CONTROL_DIR=%TOOLS_DIR%Control"
set "ACTIVE_MARKER=%CONTROL_DIR%\procmon.active"
set "RUNS_ROOT=%TOOLS_DIR:~0,-1%"
set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon64.exe"
set "PML_PATH=%RUN_DIR%\procmon.pml"

if not exist "%PROCMON_EXE%" set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon.exe"

if not exist "%PROCMON_EXE%" (
  echo ERROR Procmon executable not found under %TOOLS_DIR%Procmon
  exit /b 1
)

if not exist "%RUN_DIR%" mkdir "%RUN_DIR%"
if not exist "%CONTROL_DIR%" mkdir "%CONTROL_DIR%"

if /I not "%LOGS_DIR%"=="%RUNS_ROOT%" (
  echo ERROR logs dir must be %RUNS_ROOT%, got %LOGS_DIR%
  exit /b 1
)

for %%I in ("%RUN_DIR%") do set "RUN_DRIVE=%%~dI"
for /f "tokens=2 delims==" %%A in ('wmic logicaldisk where "DeviceID='%RUN_DRIVE%'" get FreeSpace /value ^| find "="') do set "FREE_BYTES=%%A"
if not defined FREE_BYTES (
  echo ERROR failed to read free bytes for %RUN_DRIVE%
  exit /b 1
)
set /a FREE_BYTES_MB=%FREE_BYTES:~0,-6% 2>nul
if not defined FREE_BYTES_MB (
  echo ERROR failed to evaluate free space threshold for %RUN_DRIVE%
  exit /b 1
)
if %FREE_BYTES_MB% LSS 5120 (
  echo ERROR insufficient free space on %RUN_DRIVE% for Procmon capture. Need at least 5 GiB free.
  exit /b 1
)

if exist "%ACTIVE_MARKER%" (
  set /p ACTIVE_SHA=<"%ACTIVE_MARKER%"
  call :is_procmon_running
  if "!PROCMON_RUNNING!"=="1" (
    if /I "!ACTIVE_SHA!"=="%SAMPLE_SHA256%" (
      echo OK capture already running for %SAMPLE_SHA256%
      exit /b 0
    )
    echo ERROR procmon capture already running for !ACTIVE_SHA!
    exit /b 1
  )
  del /f /q "%ACTIVE_MARKER%" 2>nul
)

call :is_procmon_running
if "!PROCMON_RUNNING!"=="1" (
  echo ERROR procmon is already running without a SentinelFlow marker. Restore the baseline snapshot before a new run.
  exit /b 1
)

del /f /q "%PML_PATH%" 2>nul
del /f /q "%RUN_DIR%\procmon.csv" 2>nul

start "" /min "%PROCMON_EXE%" /AcceptEula /Quiet /Minimized /BackingFile "%PML_PATH%"
if errorlevel 1 (
  echo ERROR failed to start Procmon capture
  exit /b 1
)

set /a ELAPSED=0
:wait_ready
call :is_procmon_running
if "!PROCMON_RUNNING!"=="1" if exist "%PML_PATH%" goto capture_ready
if %ELAPSED% GEQ 15 (
  if not "!PROCMON_RUNNING!"=="1" (
    echo ERROR Procmon did not stay running after launch
  ) else (
    echo ERROR Procmon backing file did not appear: %PML_PATH%
  )
  exit /b 1
)
ping -n 2 127.0.0.1 >nul
set /a ELAPSED+=1
goto wait_ready

:capture_ready
> "%ACTIVE_MARKER%" echo %SAMPLE_SHA256%

if not exist "%ACTIVE_MARKER%" (
  echo ERROR failed to create Procmon active marker
  exit /b 1
)

:ready
echo OK started procmon capture into %PML_PATH%
exit /b 0

:is_procmon_running
set "PROCMON_RUNNING=0"
tasklist | find /I "Procmon64.exe" >nul && set "PROCMON_RUNNING=1"
tasklist | find /I "Procmon.exe" >nul && set "PROCMON_RUNNING=1"
tasklist | find /I "Procmon64a.exe" >nul && set "PROCMON_RUNNING=1"
exit /b 0
