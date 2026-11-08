@echo off
chcp 65001 >nul
echo ==============================================
echo 开始构建 默认版本 (WN DEPLOYER 新界面)
echo ==============================================

:: 确保源图标文件夹存在
if not exist "assets_icons" mkdir "assets_icons"

:: 替换图标文件 (如果你准备了对应的源图标)
if exist "assets_icons\default_icon.png" (
    copy /Y "assets_icons\default_icon.png" "build\appicon.png"
    echo 成功替换打包图标文件 appicon.png
) else (
    echo 提示: 未发现 assets_icons\default_icon.png，使用现有默认图标。
)

if exist "assets_icons\default_icon.ico" (
    copy /Y "assets_icons\default_icon.ico" "build\windows\icon.ico"
    echo 成功替换打包图标文件 icon.ico
) else (
    echo 提示: 未发现 assets_icons\default_icon.ico，使用现有默认图标。
)

:: 注入环境变量供 Vite 识别打包类型
set VITE_APP_BRAND=default

:: 强制清理并且构建以重新编译被覆盖的图标
wails build -clean

echo.
echo ==============================================
echo 构建完成，查看 build/bin 文件夹！
echo ==============================================
pause
