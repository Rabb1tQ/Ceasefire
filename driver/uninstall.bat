@echo off
REM Force cleanup driver residuals
REM Requires Administrator privileges

echo ========================================
echo Ceasefire Driver Force Cleanup Tool
echo ========================================
echo.

REM Check administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires administrator privileges
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

set DRIVER_NAME=CeasefireDriver

echo [1/5] Stopping service...
sc stop %DRIVER_NAME% >nul 2>&1
timeout /t 3 /nobreak >nul

echo [2/5] Deleting service...
sc delete %DRIVER_NAME% >nul 2>&1
timeout /t 3 /nobreak >nul

echo [3/5] Cleaning registry...
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\%DRIVER_NAME%" /f >nul 2>&1
timeout /t 2 /nobreak >nul

echo [4/5] Waiting for system cleanup...
timeout /t 5 /nobreak >nul

echo [5/5] Verifying cleanup result...
sc query %DRIVER_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo [WARNING] Service still exists, may need to restart computer
) else (
    echo Cleanup successful!
)

echo.
echo ========================================
echo Cleanup Complete!
echo ========================================
echo.
echo Recommended actions:
echo 1. Restart computer to ensure complete cleanup
echo 2. After restart, run install.bat to reinstall
echo.
pause
