@echo off
setlocal
rem Ceasefire one-click uninstall (run as administrator): service -> driver.
rem Data files under C:\ProgramData\Ceasefire are NOT removed.
rem Pure ASCII on purpose - see the note in install-all.bat.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please run this script as administrator.
    exit /b 1
)

echo ============ 1/2 Uninstall service ============
set "SERVICE_EXE=%~dp0service\ceasefire-service.exe"
if exist "%SERVICE_EXE%" (
    "%SERVICE_EXE%" uninstall
) else (
    echo Service exe missing, falling back to sc cleanup.
    sc stop CeasefireFirewall >nul 2>&1
    timeout /t 3 /nobreak >nul
    sc delete CeasefireFirewall >nul 2>&1
)

echo ============ 2/2 Uninstall driver ============
call "%~dp0driver\uninstall-driver.bat"

echo.
echo Uninstall complete. Data files were NOT removed; delete manually if needed:
echo   C:\ProgramData\Ceasefire\          (SQLite db, GeoIP db, logs)
exit /b 0
