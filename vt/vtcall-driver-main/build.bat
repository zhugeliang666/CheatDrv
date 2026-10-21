@echo off
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" "F:\sjz-newversion\TestDriver\TestDriver.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:IntDir=x64\Release-cli\ /t:Build /nodeReuse:false > build.log 2>&1
echo EXIT_CODE=%ERRORLEVEL%
