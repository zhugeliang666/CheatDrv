# Install-XblService.ps1
# 用于单独安装 XblGameSaveProxy 服务（svchost 共享进程服务）的脚本
# 需要管理员权限运行

# Requires -RunAsAdministrator

$ServiceName = "XblGameSaveProxy"
$DisplayName = "Xbox Live Proxy"
$DllName = "XblGameSaveProxy2.dll"

# 1. 权限检查
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "此脚本必须以管理员权限运行！"
    exit 1
}

# 2. 获取 System32 路径
$sysDir = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)
$dllPath = Join-Path $sysDir $DllName

Write-Host "检测 DLL 文件是否存在..." -ForegroundColor Cyan
if (-not (Test-Path $dllPath)) {
    Write-Warning "未在 System32 目录下找到 $DllName ($dllPath)！"
    Write-Warning "请确保已将 DLL 文件复制到该路径下再启动服务。"
} else {
    Write-Host "找到 DLL 文件: $dllPath" -ForegroundColor Green
}

# 3. 加载 Win32 SCM API 定义
$WinAPITypeName = 'LeechLoader.ServiceInstaller'
if (-not ([System.Management.Automation.PSTypeName]$WinAPITypeName).Type) {
    $csUsings = ("us{0}ing System;`nus{0}ing System.Runtime.InteropServices;" -f "")
    $WinAPICode = $csUsings + @"

namespace LeechLoader {
    public static class ServiceInstaller {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern IntPtr OpenSCManagerW(IntPtr lpMachineName, IntPtr lpDatabaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern IntPtr CreateServiceW(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            IntPtr lpLoadOrderGroup,
            IntPtr lpdwTagId,
            IntPtr lpDependencies,
            IntPtr lpServiceStartName,
            IntPtr lpPassword);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }
}
"@
    Add-Type -TypeDefinition $WinAPICode -Language CSharp
}

# 4. 清理已存在的同名服务
function Remove-ExistingService {
    param([string]$Name)
    $SC_MANAGER_ALL_ACCESS = 0xF003F
    $SERVICE_STOP          = 0x0020
    $SERVICE_QUERY_STATUS  = 0x0004
    $SERVICE_DELETE        = 0x10000
    $SERVICE_STOPPED       = 0x00000001
    $SERVICE_CONTROL_STOP  = 0x00000001

    $hSCM = [LeechLoader.ServiceInstaller]::OpenSCManagerW([IntPtr]::Zero, [IntPtr]::Zero, [uint32]$SC_MANAGER_ALL_ACCESS)
    if ($hSCM -eq [IntPtr]::Zero) { return }

    $hSvc = [LeechLoader.ServiceInstaller]::OpenServiceW($hSCM, $Name, ($SERVICE_STOP -bor $SERVICE_QUERY_STATUS -bor $SERVICE_DELETE))
    if ($hSvc -ne [IntPtr]::Zero) {
        Write-Host "检测到已存在服务 $Name，正在尝试删除..." -ForegroundColor Yellow
        $status = New-Object LeechLoader.SERVICE_STATUS
        [LeechLoader.ServiceInstaller]::ControlService($hSvc, $SERVICE_CONTROL_STOP, [ref]$status) | Out-Null
        
        # 等待停止
        for ($i=0; $i -lt 10; $i++) {
            Start-Sleep -Milliseconds 200
            $status = New-Object LeechLoader.SERVICE_STATUS
            if ([LeechLoader.ServiceInstaller]::QueryServiceStatus($hSvc, [ref]$status) -and $status.dwCurrentState -eq $SERVICE_STOPPED) {
                break
            }
        }

        if ([LeechLoader.ServiceInstaller]::DeleteService($hSvc)) {
            Write-Host "服务删除指令发送成功。" -ForegroundColor Green
        }
        [LeechLoader.ServiceInstaller]::CloseServiceHandle($hSvc) | Out-Null
    }
    [LeechLoader.ServiceInstaller]::CloseServiceHandle($hSCM) | Out-Null
}

# 5. 执行安装逻辑
try {
    Remove-ExistingService -Name $ServiceName

    $SC_MANAGER_CREATE_SERVICE = 0x0002
    $SERVICE_ALL_ACCESS        = 0xF01FF
    $SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    $SERVICE_DEMAND_START      = 0x00000003
    $SERVICE_ERROR_IGNORE      = 0x00000000
    $binPath = "C:\Windows\System32\svchost.exe -k netsvcs"

    $hSCM = [LeechLoader.ServiceInstaller]::OpenSCManagerW([IntPtr]::Zero, [IntPtr]::Zero, [uint32]$SC_MANAGER_CREATE_SERVICE)
    if ($hSCM -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "无法打开服务控制管理器。 (SCM Open Failed, Win32 Error: $err)"
    }

    $hSvc = [LeechLoader.ServiceInstaller]::CreateServiceW(
        $hSCM,
        $ServiceName,
        $DisplayName,
        $SERVICE_ALL_ACCESS,
        $SERVICE_WIN32_SHARE_PROCESS,
        $SERVICE_DEMAND_START,
        $SERVICE_ERROR_IGNORE,
        $binPath,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [IntPtr]::Zero
    )

    if ($hSvc -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [LeechLoader.ServiceInstaller]::CloseServiceHandle($hSCM) | Out-Null
        throw "创建服务失败，Win32 错误代码: $err"
    }

    # 6. 配置 svchost 的注册表项 (ServiceDll)
    $regPath = "SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
    
    # 确保服务 Parameters 项已创建
    $registryKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($regPath)
    if ($null -ne $registryKey) {
        # 写入 ServiceDll (REG_EXPAND_SZ)
        $registryKey.SetValue("ServiceDll", $dllPath, [Microsoft.Win32.RegistryValueKind]::ExpandString)
        # 写入 ServiceDllUnloadOnStop (REG_DWORD)
        $registryKey.SetValue("ServiceDllUnloadOnStop", 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        $registryKey.Close()
        Write-Host "服务注册表参数配置成功。" -ForegroundColor Green
    } else {
        throw "无法创建或打开注册表路径: HKLM:\$regPath"
    }

    # 7. 将服务名加入 svchost netsvcs 组 (核心步骤，否则 svchost 会拒绝加载该服务)
    $svchostRegPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
    $svchostKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($svchostRegPath, $true)
    if ($null -ne $svchostKey) {
        $netsvcsList = [System.Collections.Generic.List[string]]($svchostKey.GetValue("netsvcs"))
        if (-not $netsvcsList.Contains($ServiceName)) {
            $netsvcsList.Add($ServiceName)
            $svchostKey.SetValue("netsvcs", [string[]]$netsvcsList, [Microsoft.Win32.RegistryValueKind]::MultiString)
            Write-Host "成功将服务 [$ServiceName] 加入 svchost netsvcs 组。" -ForegroundColor Green
        }
        $svchostKey.Close()
    } else {
        throw "无法打开注册表路径: HKLM:\$svchostRegPath"
    }

    Write-Host "服务 [$ServiceName] 安装成功！" -ForegroundColor Green
    Write-Host "正在启动服务 [$ServiceName]..." -ForegroundColor Cyan
    try {
        Start-Service $ServiceName -ErrorAction Stop
        Write-Host "服务 [$ServiceName] 启动成功！" -ForegroundColor Green
    }
    catch {
        Write-Warning "服务 [$ServiceName] 启动失败，可能由于 DLL 文件损坏、缺失或依赖项未就绪。错误信息: $_"
    }

    [LeechLoader.ServiceInstaller]::CloseServiceHandle($hSvc) | Out-Null
    [LeechLoader.ServiceInstaller]::CloseServiceHandle($hSCM) | Out-Null
}
catch {
    Write-Error "安装服务时发生错误: $_"
}
