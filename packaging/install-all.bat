@echo off
setlocal
rem Ceasefire one-click deploy (run as administrator): driver -> service -> GUI hint
rem NOTE: this file is intentionally PURE ASCII. cmd.exe mis-parses batch files
rem containing non-ASCII bytes while the console codepage is 65001 (a known
rem byte-offset parser bug), and some machines start every cmd at 65001
rem (conda hook in AutoRun, clink, or the system "Beta: UTF-8" option).
rem Pure ASCII is immune to all of that. Chinese guide: README.md here.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Please right-click this script and choose "Run as administrator".
    exit /b 1
)

echo ============ 1/3 Install and start driver ============
call "%~dp0driver\install-driver.bat"
if errorlevel 1 (
    echo [ABORT] Driver install failed, remaining steps skipped.
    exit /b 1
)

echo ============ 2/3 Install and start service ============
set "SERVICE_EXE=%~dp0service\ceasefire-service.exe"
if not exist "%SERVICE_EXE%" (
    echo [ERROR] Service executable not found: %SERVICE_EXE%
    exit /b 1
)
"%SERVICE_EXE%" uninstall >nul 2>&1
"%SERVICE_EXE%" install
if errorlevel 1 (
    echo [FAIL] Service registration failed.
    exit /b 1
)
sc start CeasefireFirewall
if errorlevel 1 (
    echo [FAIL] Service start failed. Check log: C:\ProgramData\Ceasefire\logs\ceasefire-service.log*
    exit /b 1
)
timeout /t 2 /nobreak >nul
sc query CeasefireFirewall | findstr /i RUNNING >nul
if errorlevel 1 (
    echo [FAIL] Service is not RUNNING. Check logs under C:\ProgramData\Ceasefire\logs\
    exit /b 1
)
echo [OK] Service CeasefireFirewall installed and running.

echo ============ 3/3 Deploy finished ============
echo Next: open the gui\ folder, right-click Ceasefire.exe, "Run as administrator".
echo (The service named pipe only accepts admin connections; a non-elevated GUI cannot connect.)
exit /b 0
