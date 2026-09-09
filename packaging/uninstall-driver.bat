@echo off
setlocal
rem Uninstall the Ceasefire WFP driver (run as administrator).
rem Pure ASCII on purpose - see the note in install-all.bat.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this script as administrator.
    exit /b 1
)

sc stop CeasefireDriver >nul 2>&1
timeout /t 3 /nobreak >nul
sc delete CeasefireDriver >nul 2>&1
reg delete HKLM\SYSTEM\CurrentControlSet\Services\CeasefireDriver /f >nul 2>&1
timeout /t 3 /nobreak >nul

sc query CeasefireDriver >nul 2>&1
if errorlevel 1 (
    echo [OK] Driver CeasefireDriver uninstalled.
) else (
    echo [WARN] SCM still knows the driver service; a reboot usually clears it fully.
)
exit /b 0
