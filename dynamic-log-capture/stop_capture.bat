@echo off
setlocal

set "TOOLS_DIR=%~dp0"
set "CONTROL_DIR=%TOOLS_DIR%Control"
set "ACTIVE_MARKER=%CONTROL_DIR%\procmon.active"
set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon64.exe"
set "LOGS_DIR=%~1"
set "SAMPLE_SHA256=%~2"
set "PML_PATH="

if not exist "%PROCMON_EXE%" set "PROCMON_EXE=%TOOLS_DIR%Procmon\Procmon.exe"

if not exist "%PROCMON_EXE%" (
  echo ERROR Procmon executable not found under %TOOLS_DIR%Procmon
  exit /b 1
)

if not "%LOGS_DIR%"=="" if not "%SAMPLE_SHA256%"=="" (
  set "PML_PATH=%LOGS_DIR%\%SAMPLE_SHA256%\procmon.pml"
)

taskkill /F /IM Procmon64.exe /IM Procmon.exe /IM Procmon64a.exe >nul 2>nul

set /a ELAPSED=0
:wait_exit
tasklist | find /I "Procmon64.exe" >nul
if not errorlevel 1 (
  if %ELAPSED% GEQ 15 (
    taskkill /F /IM Procmon64.exe /IM Procmon.exe /IM Procmon64a.exe >nul 2>nul
    echo ERROR Procmon64.exe still running after terminate
    exit /b 1
  )
  ping -n 2 127.0.0.1 >nul
  set /a ELAPSED+=1
  goto wait_exit
)

tasklist | find /I "Procmon.exe" >nul
if not errorlevel 1 (
  if %ELAPSED% GEQ 15 (
    taskkill /F /IM Procmon64.exe /IM Procmon.exe /IM Procmon64a.exe >nul 2>nul
    echo ERROR Procmon.exe still running after terminate
    exit /b 1
  )
  ping -n 2 127.0.0.1 >nul
  set /a ELAPSED+=1
  goto wait_exit
)

tasklist | find /I "Procmon64a.exe" >nul
if not errorlevel 1 (
  if %ELAPSED% GEQ 15 (
    taskkill /F /IM Procmon64.exe /IM Procmon.exe /IM Procmon64a.exe >nul 2>nul
    echo ERROR Procmon64a.exe still running after terminate
    exit /b 1
  )
  ping -n 2 127.0.0.1 >nul
  set /a ELAPSED+=1
  goto wait_exit
)

del /f /q "%ACTIVE_MARKER%" 2>nul
if not "%PML_PATH%"=="" call :wait_for_pml "%PML_PATH%"
echo OK stopped procmon capture
exit /b 0

:wait_for_pml
set "TARGET_PML=%~1"
set /a PML_ELAPSED=0
:wait_for_pml_loop
if exist "%TARGET_PML%" exit /b 0
if %PML_ELAPSED% GEQ 15 (
  echo ERROR Procmon backing file not found after stop: %TARGET_PML%
  exit /b 1
)
ping -n 2 127.0.0.1 >nul
set /a PML_ELAPSED+=1
goto wait_for_pml_loop
