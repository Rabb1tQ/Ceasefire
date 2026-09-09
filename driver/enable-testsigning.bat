@echo off
REM 启用 Windows 测试模式
REM 需要管理员权限运行

echo ========================================
echo 启用 Windows 测试签名模式
echo ========================================
echo.

REM 检查管理员权限
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [错误] 此脚本需要管理员权限运行
    echo 请右键点击此文件，选择"以管理员身份运行"
    pause
    exit /b 1
)

echo 正在启用测试签名模式...
bcdedit /set testsigning on

if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo 测试签名模式已启用！
    echo ========================================
    echo.
    echo 重要提示:
    echo 1. 必须重启电脑才能生效
    echo 2. 重启后桌面右下角会显示"测试模式"水印
    echo 3. 这允许加载未签名的驱动程序
    echo.
    echo 如需禁用测试模式，运行: bcdedit /set testsigning off
    echo.
    set /p REBOOT="是否现在重启电脑? (Y/N): "
    if /i "%REBOOT%"=="Y" (
        shutdown /r /t 10 /c "重启以启用测试签名模式"
        echo 系统将在 10 秒后重启...
    ) else (
        echo 请稍后手动重启电脑
    )
) else (
    echo.
    echo [错误] 启用测试签名模式失败
    echo 请确保以管理员身份运行此脚本
)

echo.
pause
