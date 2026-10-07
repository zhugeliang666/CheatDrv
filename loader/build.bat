@echo off
setlocal

set "CONFIG=Release"
if /i "%~1"=="debug" set "CONFIG=Debug"
if /i "%~1"=="clean" goto do_clean

set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
if not exist "%MSBUILD%" (
    set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
)

echo [*] 使用 MSBuild: "%MSBUILD%"
echo [*] 配置: %CONFIG% ^| x64
echo.

"%MSBUILD%" "%~dp0loader.sln" /p:Configuration=%CONFIG% /p:Platform=x64 /v:m /nologo
if errorlevel 1 (
    echo [x] 编译失败！
    exit /b 1
)

echo [v] 编译成功: "%~dp0bin\%CONFIG%\loader.exe"
exit /b 0

:do_clean
echo [*] 清理输出...
if exist "%~dp0bin" rd /s /q "%~dp0bin"
if exist "%~dp0build" rd /s /q "%~dp0build"
if exist "%~dp0.vs" rd /s /q "%~dp0.vs"
echo [v] 清理完成。
exit /b 0
