@echo off
setlocal
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
if not exist "%MSBUILD%" set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
"%MSBUILD%" "%~dp0VtHypervisor.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:IntDir=x64\Release-cli\ /t:Build /nodeReuse:false > "%~dp0build.log" 2>&1
echo EXIT_CODE=%ERRORLEVEL%
exit /b %ERRORLEVEL%
