@echo off
chcp 65001 >nul
echo ========================================
echo   WeChatDecrypt 打包脚本
echo ========================================
echo.

:: 检查 pyinstaller
where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [!] 未找到 pyinstaller，正在安装...
    pip install pyinstaller
)

echo [*] 开始打包...
echo.

pyinstaller --noconfirm --onefile --console --name "WeChatDecrypt" ^
    --add-data "main.py;." ^
    --add-data "config.py;." ^
    --add-data "decrypt_db.py;." ^
    --add-data "export_messages.py;." ^
    --add-data "voice_to_mp3.py;." ^
    --add-data "find_all_keys.py;." ^
    --add-data "find_all_keys_windows.py;." ^
    --add-data "find_all_keys_linux.py;." ^
    --add-data "key_scan_common.py;." ^
    --add-data "key_utils.py;." ^
    --add-data "decode_image.py;." ^
    --add-data "find_image_key.py;." ^
    --add-data "find_image_key_monitor.py;." ^
    --add-data "monitor.py;." ^
    --add-data "monitor_web.py;." ^
    --add-data "mcp_server.py;." ^
    --add-data "config.example.json;." ^
    --collect-all pilk ^
    app_gui.py

if errorlevel 1 (
    echo.
    echo [!] 打包失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo   打包完成！
echo   输出: dist\WeChatDecrypt.exe
for %%F in (dist\WeChatDecrypt.exe) do echo   大小: %%~zF bytes
echo ========================================
echo.
pause
