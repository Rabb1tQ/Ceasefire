@echo off
REM CeasefireDriver Installation Script
REM Requires Administrator privileges

echo ========================================
echo Ceasefire Driver Installer
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

REM Set driver path
set DRIVER_NAME=CeasefireDriver
set DRIVER_PATH=%~dp0bin\x64\Release\%DRIVER_NAME%.sys
set DRIVER_DISPLAY_NAME=Ceasefire Firewall Driver

echo Driver path: %DRIVER_PATH%
echo.

REM Check if driver file exists
if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver file not found: %DRIVER_PATH%
    echo Please compile the driver first
    pause
    exit /b 1
)

REM Stop and delete existing service
echo [1/4] Checking and stopping existing service...
sc query %DRIVER_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo Found existing service, stopping...
    sc stop %DRIVER_NAME% >nul 2>&1
    echo Waiting for service to stop...
    timeout /t 3 /nobreak >nul
    
    echo Deleting service...
    sc delete %DRIVER_NAME% >nul 2>&1
    echo Waiting for system to cleanup...
    timeout /t 5 /nobreak >nul
    echo Old service deleted
) else (
    echo No existing service found
)
echo.

REM Create service
echo [2/4] Creating driver service...
sc create %DRIVER_NAME% type= kernel start= system binPath= "%DRIVER_PATH%" DisplayName= "%DRIVER_DISPLAY_NAME%"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to create service
    pause
    exit /b 1
)
echo Service created successfully
echo.

REM Start service
echo [3/4] Starting driver service...
sc start %DRIVER_NAME%
if %errorLevel% neq 0 (
    echo [WARNING] Failed to start service
    echo.
    echo Possible reasons:
    echo 1. Driver is not signed - need to enable test signing mode
    echo 2. Driver code has issues
    echo.
    echo To enable test signing mode, run:
    echo    bcdedit /set testsigning on
    echo Then restart your computer and run this script again
    echo.
    pause
    exit /b 1
)
echo Service started successfully
echo.

REM Verify service status
echo [4/4] Verifying service status...
sc query %DRIVER_NAME%
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo Driver service name: %DRIVER_NAME%
echo Display name: %DRIVER_DISPLAY_NAME%
echo.
echo Management commands:
echo   Check status: sc query %DRIVER_NAME%
echo   Stop service: sc stop %DRIVER_NAME%
echo   Start service: sc start %DRIVER_NAME%
echo   Uninstall: run uninstall.bat
echo.
pause
