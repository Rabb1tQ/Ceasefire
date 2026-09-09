@echo off
REM Run PowerShell signing script with administrator privileges

echo Starting PowerShell signing script...
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0sign-driver.ps1"

pause
