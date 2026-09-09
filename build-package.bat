@echo off
setlocal enabledelayedexpansion

rem build-package.bat - Ceasefire one-shot build & package script
rem (replaces the former build-package.ps1)
rem
rem usage:
rem   build-package.bat              full build (driver Release + service + GUI)
rem   build-package.bat /debug       driver Debug config (KdPrint for troubleshooting)
rem   build-package.bat /skipgui     skip GUI (rebuild driver+service only)
rem   build-package.bat /skipdriver  skip driver
rem   build-package.bat /skipservice skip service
rem   build-package.bat /zip         create zip of release\ via built-in bsdtar
rem   switches are combinable and case-insensitive; unknown switch prints usage and exits.
rem
rem NOTE: this file is intentionally PURE ASCII. cmd.exe mis-parses batch files
rem containing non-ASCII bytes while the console codepage is 65001 (byte-offset
rem parser bug), and some machines start every cmd at 65001 (conda hook in the
rem cmd AutoRun, clink, or the system-wide "Beta: Use Unicode UTF-8" option).
rem GBK does not help there either - pure ASCII is the only portable choice.
rem Keep it ASCII-only. Chinese guide lives in packaging\README.md (UTF-8).
rem Also: no "call :label" subroutines and no pipes inside nested for-loops;
rem escape literal parens in echo lines inside if-blocks.
rem
rem output: release\ (green package; zip it, copy to the test machine,
rem run install-all.bat as administrator there)

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "RELEASE=%ROOT%\release"

set "DriverConfig=Release"
set "SkipDriver=0"
set "SkipService=0"
set "SkipGui=0"
set "MakeZip=0"

rem ---------- parse arguments ----------
for %%a in (%*) do (
    if /i "%%a"=="/debug"       ( set "DriverConfig=Debug" ) else if /i "%%a"=="/skipdriver"  ( set "SkipDriver=1" ) else if /i "%%a"=="/skipservice" ( set "SkipService=1" ) else if /i "%%a"=="/skipgui" ( set "SkipGui=1" ) else if /i "%%a"=="/zip" ( set "MakeZip=1" ) else (
        echo [ERROR] Unknown switch: %%a
        echo.
        goto :usage
    )
)
if "%SkipDriver%%SkipService%%SkipGui%"=="111" (
    echo [ERROR] driver, service and GUI are all skipped - nothing to do.
    goto :usage
)

echo ========== dependency probe ==========
echo start: %time%

set "MSBUILD="
if "%SkipDriver%"=="0" (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" (
        echo [FAIL] vswhere not found ^(!VSWHERE!^). Install Visual Studio with the "Desktop development with C++" workload and the WDK.
        exit /b 1
    )
    for /f "usebackq delims=" %%i in (`"!VSWHERE!" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        if not defined MSBUILD set "MSBUILD=%%i"
    )
    if not defined MSBUILD (
        echo [FAIL] vswhere found Visual Studio but no MSBuild. Install the "Desktop development with C++" workload.
        exit /b 1
    )
    echo MSBuild : !MSBUILD!
)

if "%SkipService%"=="0" (
    where cargo >nul 2>nul
    if errorlevel 1 (
        echo [FAIL] cargo not found. Install Rust ^(https://rustup.rs^).
        exit /b 1
    )
    echo cargo   : found
)

if "%SkipGui%"=="0" (
    where npm >nul 2>nul
    if errorlevel 1 (
        echo [FAIL] npm not found. Install Node.js LTS ^(https://nodejs.org^).
        exit /b 1
    )
    echo npm     : found
)
echo [OK] dependency probe passed  %time%

rem ---------- 1. driver ----------
if "%SkipDriver%"=="0" (
    echo.
    echo ========== build driver ^(%DriverConfig%/x64^) ==========
    echo start: %time%
    rem clean old bin/obj first: a stale locked .sys once caused LNK1104
    if exist "%ROOT%\driver\bin" rd /s /q "%ROOT%\driver\bin"
    if exist "%ROOT%\driver\obj" rd /s /q "%ROOT%\driver\obj"
    call "!MSBUILD!" "%ROOT%\driver\CeasefireDriver.sln" /p:Configuration=%DriverConfig% /p:Platform=x64 /m /v:m /nologo
    if errorlevel 1 goto :fail_driver
    if not exist "%ROOT%\driver\bin\x64\%DriverConfig%\CeasefireDriver.sys" (
        echo [FAIL] build finished but artifact not found: driver\bin\x64\%DriverConfig%\CeasefireDriver.sys
        goto :fail_abort
    )
    rem signing: sign-driver.ps1 has Release paths hardcoded, Release only; needs admin.
    rem HARD FAIL on any signing problem: an unsigned driver only fails later on the
    rem target machine (sc start error 577), so fail early and keep release\ clean.
    if "%DriverConfig%"=="Release" (
        net session >nul 2>nul
        if errorlevel 1 (
            echo [FAIL] driver signing requires administrator privileges. Re-run build-package.bat from an elevated console.
            goto :fail_abort
        )
        if not exist "%ROOT%\driver\sign-driver.ps1" (
            echo [FAIL] signing script not found: driver\sign-driver.ps1
            goto :fail_abort
        )
        echo Signing the driver ^(sign-driver.ps1^)...
        call powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%ROOT%\driver\sign-driver.ps1"
        if errorlevel 1 (
            echo [FAIL] driver signing failed or unverified
            goto :fail_abort
        )
        powershell -NoProfile -NonInteractive -Command "if ((Get-AuthenticodeSignature -FilePath '%ROOT%\driver\bin\x64\Release\CeasefireDriver.sys').Status -ne 'Valid') { exit 1 }"
        if errorlevel 1 (
            echo [FAIL] driver signing failed or unverified
            goto :fail_abort
        )
        echo driver signing done and verified
    ) else (
        echo [HINT] Debug driver: signing skipped ^(sign-driver.ps1 supports Release only^). Test machine needs test signing mode.
    )
    echo [OK] driver built  %time%
)

rem ---------- 2. service ----------
if "%SkipService%"=="0" (
    echo.
    echo ========== build service ^(cargo build --release^) ==========
    echo start: %time%
    pushd "%ROOT%\service"
    call cargo build --release
    if errorlevel 1 ( popd & goto :fail_service )
    if not exist "target\release\ceasefire-service.exe" (
        popd
        echo [FAIL] artifact not found: service\target\release\ceasefire-service.exe
        goto :fail_abort
    )
    popd
    echo [OK] service built  %time%
)

rem ---------- 3. GUI ----------
if "%SkipGui%"=="0" (
    echo.
    echo ========== build GUI ^(tauri build^) ==========
    echo start: %time%
    pushd "%ROOT%\gui"
    if not exist "node_modules" (
        echo node_modules missing, running npm install...
        call npm install
        if errorlevel 1 ( popd & goto :fail_gui )
    )
    call npm run tauri build
    if errorlevel 1 ( popd & goto :fail_gui )
    if not exist "src-tauri\target\release\Ceasefire.exe" if not exist "src-tauri\target\release\app.exe" (
        popd
        echo [FAIL] GUI artifact exe not found under gui\src-tauri\target\release\
        goto :fail_abort
    )
    popd
    echo [OK] GUI built  %time%
)

rem ---------- 4. collect artifacts ----------
echo.
echo ========== collect artifacts into %RELEASE% ==========
echo start: %time%
if exist "%RELEASE%" rd /s /q "%RELEASE%"
mkdir "%RELEASE%\driver" "%RELEASE%\service" "%RELEASE%\gui" || goto :fail_abort

if "%SkipDriver%"=="0" (
    for %%f in ("%ROOT%\driver\bin\x64\%DriverConfig%\CeasefireDriver.sys" "%ROOT%\packaging\install-driver.bat" "%ROOT%\packaging\uninstall-driver.bat") do (
        if not exist "%%~f" (
            echo [FAIL] missing artifact: %%~f
            goto :fail_abort
        )
        copy /y "%%~f" "%RELEASE%\driver\" >nul || goto :fail_copy
        echo   + driver\%%~nxf
    )
    if exist "%ROOT%\driver\CeasefireTestCert.cer" (
        copy /y "%ROOT%\driver\CeasefireTestCert.cer" "%RELEASE%\driver\" >nul || goto :fail_copy
        echo   + driver\CeasefireTestCert.cer
    ) else (
        echo   - skipped ^(not present^): driver\CeasefireTestCert.cer
    )
)

if "%SkipService%"=="0" (
    for %%f in ("%ROOT%\service\target\release\ceasefire-service.exe" "%ROOT%\service\GeoLite2-City.mmdb") do (
        if not exist "%%~f" (
            echo [FAIL] missing artifact: %%~f
            goto :fail_abort
        )
        copy /y "%%~f" "%RELEASE%\service\" >nul || goto :fail_copy
        echo   + service\%%~nxf
    )
)

if "%SkipGui%"=="0" (
    rem tauri output exe may be productName or cargo bin name; always ship as Ceasefire.exe
    set "GUI_SRC=%ROOT%\gui\src-tauri\target\release\Ceasefire.exe"
    if not exist "!GUI_SRC!" set "GUI_SRC=%ROOT%\gui\src-tauri\target\release\app.exe"
    if not exist "!GUI_SRC!" (
        echo [FAIL] missing artifact: gui\src-tauri\target\release\Ceasefire.exe
        goto :fail_abort
    )
    copy /y "!GUI_SRC!" "%RELEASE%\gui\" >nul || goto :fail_copy
    for %%f in ("!GUI_SRC!") do (
        echo   + gui\%%~nxf
        if /i not "%%~nxf"=="Ceasefire.exe" (
            move /y "%RELEASE%\gui\%%~nxf" "%RELEASE%\gui\Ceasefire.exe" >nul || goto :fail_copy
            echo   * renamed to gui\Ceasefire.exe
        )
    )
)

for %%f in ("%ROOT%\packaging\install-all.bat" "%ROOT%\packaging\uninstall-all.bat" "%ROOT%\packaging\README.md") do (
    if not exist "%%~f" (
        echo [FAIL] missing file: %%~f
        goto :fail_abort
    )
    copy /y "%%~f" "%RELEASE%\" >nul || goto :fail_copy
    echo   + %%~nxf
)
echo [OK] artifacts collected  %time%

rem ---------- 5. zip (optional) ----------
if "%MakeZip%"=="1" (
    echo.
    echo ========== create zip ==========
    echo start: %time%
    set "LDT="
    for /f "tokens=2 delims==" %%i in ('wmic os get localdatetime /value 2^>nul') do set "LDT=%%i"
    if defined LDT ( set "TODAY=!LDT:~0,8!" ) else ( set "TODAY=%date:~0,4%%date:~5,2%%date:~8,2%" )
    set "ZIPFILE=%RELEASE%\Ceasefire-!TODAY!-%DriverConfig%.zip"
    set "ZIPLIST="
    if "%SkipDriver%"=="0"   set "ZIPLIST=!ZIPLIST! driver"
    if "%SkipService%"=="0"  set "ZIPLIST=!ZIPLIST! service"
    if "%SkipGui%"=="0"      set "ZIPLIST=!ZIPLIST! gui"
    set "ZIPLIST=!ZIPLIST! install-all.bat uninstall-all.bat README.md"
    tar -a -c -f "!ZIPFILE!" -C "%RELEASE%" !ZIPLIST!
    if errorlevel 1 (
        echo [FAIL] zip creation failed ^(tar exit code non-zero^).
        goto :fail_abort
    )
    echo [OK] zip created: !ZIPFILE!  %time%
)

rem ---------- 6. manifest ----------
echo.
echo ========== artifact manifest ==========
set "HASHTMP=%TEMP%\ceasefire-md5.txt"
pushd "%RELEASE%"
for /r %%f in (*.*) do (
    set "REL=%%~ff"
    set "REL=!REL:%RELEASE%\=!"
    set "HASH="
    certutil -hashfile "%%~ff" MD5 > "!HASHTMP!" 2>nul
    for /f "usebackq skip=1 delims=" %%h in ("!HASHTMP!") do if not defined HASH set "HASH=%%h"
    echo   !REL!    [%%~zf bytes]    MD5: !HASH!
)
popd
del /q "!HASHTMP!" >nul 2>nul

echo.
echo ****************************************************************
echo  Packaging done. Copy the whole release\ folder to the test
echo  machine, then run install-all.bat as administrator there,
echo  and start gui\Ceasefire.exe as administrator.
echo ****************************************************************
endlocal
exit /b 0

:usage
echo usage: build-package.bat [/debug] [/skipgui] [/skipdriver] [/skipservice] [/zip]
echo   (no args)      full build: driver Release + service + GUI
echo   /debug         build driver as Debug (KdPrint troubleshooting)
echo   /skipgui       skip GUI (driver + service only)
echo   /skipdriver    skip driver
echo   /skipservice   skip service
echo   /zip           zip release\ contents after packaging
endlocal
exit /b 2

:fail_driver
echo [FAIL] driver build failed (MSBuild exit code non-zero), aborted.
goto :fail_abort
:fail_service
echo [FAIL] service build failed (cargo build exit code non-zero), aborted.
goto :fail_abort
:fail_gui
echo [FAIL] GUI build failed (npm run tauri build exit code non-zero), aborted.
goto :fail_abort
:fail_copy
echo [FAIL] copying an artifact failed.
:fail_abort
echo Packaging skipped to avoid mixing old and new artifacts. Fix the issue and retry.
endlocal
exit /b 1
