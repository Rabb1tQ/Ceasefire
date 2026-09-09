@echo off
setlocal
rem Install the Ceasefire WFP driver (run as administrator).
rem The .sys file sits next to this script. Pure ASCII on purpose - see
rem the note in install-all.bat.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this script as administrator.
    exit /b 1
)

set "DRIVER_PATH=%~dp0CeasefireDriver.sys"
if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver file not found: %DRIVER_PATH%
    exit /b 1
)

rem Remove a possible previous instance
sc stop CeasefireDriver >nul 2>&1
timeout /t 2 /nobreak >nul
sc delete CeasefireDriver >nul 2>&1

sc create CeasefireDriver type= kernel start= system binPath= "%DRIVER_PATH%" DisplayName= "Ceasefire Firewall Driver"
if errorlevel 1 (
    echo [ERROR] Failed to create the driver service.
    exit /b 1
)

sc start CeasefireDriver
if errorlevel 1 (
    echo [FAIL] Driver start failed. Most common cause: test signing mode is off.
    echo        Run as admin: bcdedit /set testsigning on  then reboot, then run this script again.
    exit /b 1
)

timeout /t 2 /nobreak >nul
sc query CeasefireDriver | findstr /i RUNNING >nul
if errorlevel 1 (
    echo [FAIL] Driver service is not RUNNING. Check with: sc query CeasefireDriver
    exit /b 1
)
echo [OK] Driver CeasefireDriver installed and started.
exit /b 0
