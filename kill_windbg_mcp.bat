@echo off
setlocal enabledelayedexpansion
title 清理 WinDbg MCP 进程

echo ========================================================
echo          正在终止 WinDbg MCP 及关联调试器进程...
echo ========================================================

:: 1. 强制终止常规命名的主程序及底层调试引擎
taskkill /f /im mcp-windbg.exe >nul 2>&1
taskkill /f /im cdb.exe >nul 2>&1
taskkill /f /im kd.exe >nul 2>&1

:: 2. 通过 PowerShell 精确查找并终止命令行包含 mcp-windbg 的 uv/uvx/python 进程（防误杀其他正常 Python 进程）
powershell -NoProfile -Command "$myPid = $PID; $targets = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $myPid -and ($_.Name -eq 'mcp-windbg.exe' -or $_.Name -eq 'cdb.exe' -or $_.Name -eq 'kd.exe' -or ($_.CommandLine -like '*mcp-windbg*' -and $_.Name -ne 'powershell.exe') -or ($_.CommandLine -like '*AUO20t6MwlvDM40c*' -and $_.Name -ne 'powershell.exe')) }; if ($targets) { foreach ($p in $targets) { Write-Host ('[已终止] PID: ' + $p.ProcessId + ' | 映像: ' + $p.Name); Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; } } else { Write-Host '[信息] 未检测到残留的 WinDbg MCP 进程。' -ForegroundColor Green; }"

echo ========================================================
echo                    清理完成！
echo ========================================================
ping -n 3 127.0.0.1 >nul
