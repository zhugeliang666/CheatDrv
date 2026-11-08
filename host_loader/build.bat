@echo off
REM Build LeechLoader Project Batch Script

SET MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"

REM Check Community Edition if Professional does not exist
if not exist %MSBUILD% (
    SET MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
)

if not exist %MSBUILD% (
    echo Error: MSBuild.exe not found.
    echo Please ensure Visual Studio 2022 is installed correctly.
    pause
    exit /b 1
)

echo ========================================
echo Please select build configuration:
echo 1. Debug x64 (Standard Debug)
echo 2. Release_No_LLVM x64 (No Obfuscation Release)
echo 3. Release x64 (OLLVM Obfuscated Release)
echo ========================================
set /p CHOICE="Enter choice (1-3) [Default 1]: "

if "%CHOICE%"=="" set CHOICE=1

if "%CHOICE%"=="1" (
    set CONFIG=Debug
) else if "%CHOICE%"=="2" (
    set CONFIG=Release_No_LLVM
) else if "%CHOICE%"=="3" (
    set CONFIG=Release
) else (
    echo Invalid choice!
    pause
    exit /b 1
)

echo.
echo Compiling %CONFIG% x64 configuration...
%MSBUILD% LeechLoader\LeechLoader.vcxproj /p:Configuration=%CONFIG% /p:Platform=x64 /t:Build /v:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ========================================
    echo Build Failed! Please check errors.
    echo ========================================
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build Succeeded!
echo ========================================
echo.
pause
