package backend

import (
	"context"
	"crypto/md5"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

//go:embed dll/host_loader.dll dll/close_defender.exe dll/zadig.exe dll/file.docx
var dllFS embed.FS

// ResponseResult 对应 C 结构体 response_result
type ResponseResult struct {
	Result int    `json:"result"`
	Msg    string `json:"msg"`
}

// FrontendResponse 返回给前端的响应结构，result 为布尔类型
type FrontendResponse struct {
	Result bool   `json:"result"` // true 表示成功，false 表示失败
	Msg    string `json:"msg"`    // 消息内容
}

// LogInfo 对应 C 结构体 CLogInfo
type LogInfo struct {
	Info  string `json:"info"`  // 日志信息
	Level int    `json:"level"` // 日志级别
}

// DLL 函数指针
var (
	procInitConfig     *syscall.Proc
	procGetLogList     *syscall.Proc
	procFreeLogList    *syscall.Proc
	procClearLogList   *syscall.Proc
	procGetConnectMode *syscall.Proc
	procGetApiUrl      *syscall.Proc
)

// App struct
type App struct {
	ctx         context.Context
	dll         *syscall.DLL
	dllTempPath string
}

// NewApp 创建新的 App 实例
func NewApp() *App {
	return &App{}
}

// Startup 在应用启动时调用
func (a *App) Startup(ctx context.Context) {
	// a.ctx = ctx
	// // 在启动时加载 DLL，默认写到程序目录
	// if err := a.loadDLL(false); err != nil {
	// 	fmt.Printf("加载 DLL 失败: %v\n", err)
	// 	os.Exit(1)
	// }
}

// Shutdown 在应用关闭时调用
func (a *App) Shutdown(ctx context.Context) {

}

// LoadDLL 从嵌入的文件系统中提取并加载 DLL
func (a *App) LoadDLL(useLocalDir bool) *FrontendResponse {
	fmt.Println("正在加载嵌入的 DLL (host_loader.dll)...")

	// 读取嵌入的 DLL 文件
	dllData, err := dllFS.ReadFile("dll/host_loader.dll")
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("读取嵌入的 DLL 文件失败: %v", err)}
	}

	// 获取目标目录
	var targetDir string
	var targetFile string

	if useLocalDir {
		exePath, err := os.Executable()
		if err != nil {
			return &FrontendResponse{Result: false, Msg: fmt.Sprintf("获取程序路径失败: %v", err)}
		}
		targetDir = filepath.Dir(exePath)
		targetFile = filepath.Join(targetDir, "host_loader.dll")
	} else {
		targetDir = os.TempDir()
		// 加载之前删除host_loader_xxx.dll
		files, _ := filepath.Glob(filepath.Join(targetDir, "host_loader_*.dll"))
		for _, f := range files {
			os.Remove(f)
		}

		// 使用包含 PID 的唯一文件名，避免多实例冲突
		targetFile = filepath.Join(targetDir, fmt.Sprintf("host_loader_%d.dll", os.Getpid()))
	}

	// 写入文件
	err = os.WriteFile(targetFile, dllData, 0644)
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("写入 DLL 文件失败: %v", err)}
	}

	a.dllTempPath = targetFile
	fmt.Printf("DLL 已释放至: %s\n", targetFile)

	// 加载 DLL
	dll, err := syscall.LoadDLL(targetFile)
	if err != nil {
		// 尝试提供详细错误
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("无法加载 DLL (请检查依赖项或 32/64 位兼容性): %v", err)}
	}

	a.dll = dll

	// 验证并预加载函数指针
	if err := a.validateDLL(); err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("DLL 完整性验证失败: %v", err)}
	}

	return &FrontendResponse{Result: true, Msg: "DLL 加载成功"}
}

// validateDLL 验证 DLL 的完整性，并将函数指针预加载到全局变量
func (a *App) validateDLL() error {
	if a.dll == nil {
		return fmt.Errorf("DLL 未加载")
	}

	fmt.Println("开始验证并预加载 DLL 导出函数...")

	// 定义函数指针信息结构
	type funcInfo struct {
		proc **syscall.Proc
		name string
	}

	// 定义所有需要加载的函数
	funcs := []funcInfo{
		{&procInitConfig, "InitConfig"},
		{&procGetLogList, "GetLogList"},
		{&procFreeLogList, "FreeLogList"},
		{&procClearLogList, "ClearLogList"},
		{&procGetConnectMode, "getConnectMode"},
		{&procGetApiUrl, "GetApiUrl"},
	}

	var missingFuncs []string

	// 加载并验证所有函数指针
	for _, f := range funcs {
		proc, err := a.dll.FindProc(f.name)
		if err != nil {
			missingFuncs = append(missingFuncs, f.name)
			continue
		}

		if proc == nil {
			missingFuncs = append(missingFuncs, f.name)
			continue
		}

		// 存储到全局变量
		*f.proc = proc
		fmt.Printf("✓ 成功加载函数: %s (地址: 0x%x)\n", f.name, proc.Addr())
	}

	if len(missingFuncs) > 0 {
		return fmt.Errorf("缺少必需的导出函数: %v", missingFuncs)
	}

	fmt.Println("DLL 完整性验证通过，所有函数指针已就绪")
	return nil
}

// getProcAddress 获取预加载的函数指针
func (a *App) getProcAddress(funcName string) (*syscall.Proc, error) {
	if a.dll == nil {
		return nil, fmt.Errorf("DLL 未加载")
	}

	var proc *syscall.Proc
	switch funcName {
	case "InitConfig":
		proc = procInitConfig
	case "GetLogList":
		proc = procGetLogList
	case "FreeLogList":
		proc = procFreeLogList
	case "ClearLogList":
		proc = procClearLogList
	case "getConnectMode":
		proc = procGetConnectMode
	case "GetApiUrl":
		proc = procGetApiUrl
	default:
		return nil, fmt.Errorf("未定义的函数: %s", funcName)
	}

	if proc == nil {
		return nil, fmt.Errorf("函数 %s 的指针尚未初始化", funcName)
	}

	return proc, nil
}

// callDLLFunction 统一调用接口
func (a *App) callDLLFunction(funcName string, args ...uintptr) (*ResponseResult, error) {
	proc, err := a.getProcAddress(funcName)
	if err != nil {
		return &ResponseResult{Result: -1, Msg: err.Error()}, err
	}

	ret, _, callErr := proc.Call(args...)
	if ret == 0 {
		errMsg := fmt.Sprintf("%s 调用空返回", funcName)
		if callErr != nil {
			errMsg = fmt.Sprintf("%s 调用错误: %v", funcName, callErr)
		}
		return &ResponseResult{Result: -1, Msg: errMsg}, fmt.Errorf(errMsg)
	}

	return a.parseResponseResult(ret, funcName)
}

// parseResponseResult 解析结构体
func (a *App) parseResponseResult(ptr uintptr, funcName string) (*ResponseResult, error) {
	if ptr == 0 {
		return nil, fmt.Errorf("返回指针为空")
	}

	pResult := (*struct {
		Result int
		Msg    uintptr
	})(unsafe.Pointer(ptr))

	var msg string
	if pResult.Msg != 0 {
		msgBytes := make([]byte, 0, 256)
		for i := uintptr(0); i < 1024; i++ {
			b := *(*byte)(unsafe.Pointer(pResult.Msg + i))
			if b == 0 {
				break
			}
			msgBytes = append(msgBytes, b)
		}
		msg = string(msgBytes)
	} else {
		msg = "None"
	}

	return &ResponseResult{
		Result: pResult.Result,
		Msg:    msg,
	}, nil
}

// InitConfig 后端接口：初始化配置
func (a *App) InitConfig() *FrontendResponse {
	result, err := a.callDLLFunction("InitConfig")
	if err != nil {
		return &FrontendResponse{Result: false, Msg: err.Error()}
	}

	// 原逻辑：1 代表成功
	return &FrontendResponse{
		Result: result.Result == 1,
		Msg:    result.Msg,
	}
}

// GetConnectMode 获取当前连接模式（1 为 USB）
func (a *App) GetConnectMode() int {
	proc, err := a.getProcAddress("getConnectMode")
	if err != nil {
		fmt.Printf("GetConnectMode proc not found: %v\n", err)
		return 0
	}
	ret, _, _ := proc.Call()
	return int(ret)
}

// GetApiUrl 从 DLL 中获取当前环境的 API 地址（对应 DLL_EXPORT const char* GetApiUrl()）
func (a *App) GetApiUrl() string {
	proc, err := a.getProcAddress("GetApiUrl")
	if err != nil {
		fmt.Printf("GetApiUrl proc not found: %v\n", err)
		return ""
	}
	ret, _, _ := proc.Call()
	if ret == 0 {
		return ""
	}
	// 读取 C 字符串（以 null 结尾）
	var result []byte
	for i := uintptr(0); i < 2048; i++ {
		b := *(*byte)(unsafe.Pointer(ret + i))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	return string(result)
}

// GetLogList 后端接口：获取日志列表
func (a *App) GetLogList() []LogInfo {
	getLogListProc, err := a.getProcAddress("GetLogList")
	if err != nil {
		return []LogInfo{}
	}

	var count int32 = 0
	ret, _, _ := getLogListProc.Call(uintptr(unsafe.Pointer(&count)))

	if ret == 0 || count == 0 {
		return []LogInfo{}
	}

	type CLogInfo struct {
		Info  uintptr
		Level int32
	}

	logs := make([]LogInfo, count)
	cLogPtr := ret
	size := unsafe.Sizeof(CLogInfo{})

	for i := int32(0); i < count; i++ {
		cLog := (*CLogInfo)(unsafe.Pointer(cLogPtr))

		var info string
		if cLog.Info != 0 {
			infoBytes := make([]byte, 0, 256)
			for j := uintptr(0); j < 4096; j++ {
				b := *(*byte)(unsafe.Pointer(cLog.Info + j))
				if b == 0 {
					break
				}
				infoBytes = append(infoBytes, b)
			}
			info = string(infoBytes)
		}

		logs[i] = LogInfo{
			Info:  info,
			Level: int(cLog.Level),
		}
		cLogPtr += size
	}

	// 释放 C 分配的内存
	a.freeLogList(ret, count)
	return logs
}

func (a *App) freeLogList(ptr uintptr, count int32) {
	freeLogListProc, err := a.getProcAddress("FreeLogList")
	if err != nil {
		return
	}
	freeLogListProc.Call(ptr, uintptr(count))
}

// ClearLogList 后端接口：清空日志
func (a *App) ClearLogList() {
	clearLogListProc, err := a.getProcAddress("ClearLogList")
	if err != nil {
		return
	}
	clearLogListProc.Call()
}

// GetTempFilePath 调试用
func (a *App) GetTempFilePath() string {
	return a.dllTempPath
}

// GetSelfMD5Hex 获取当前程序的 MD5（在内存中完全撤销对 PE 的 patch，从而与未被 patch 之前的原文件 MD5 严格一致）
func (a *App) GetSelfMD5Hex() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(exePath)
	if err != nil {
		return ""
	}

	// 制作副本，我们将要在内存中撤销由 patchPEAddModeCfg 做的修改
	buf := make([]byte, len(data))
	copy(buf, data)

	// --- 尝试还原 PE 结构到注入 .modcfg 之前的状态 ---
	if len(buf) >= 0x40 && binary.LittleEndian.Uint16(buf[0:2]) == 0x5A4D {
		peOffset := int(binary.LittleEndian.Uint32(buf[0x3C:0x40]))
		if peOffset+4+20 <= len(buf) && string(buf[peOffset:peOffset+4]) == "PE\x00\x00" {
			fhBase := peOffset + 4
			numSections := int(binary.LittleEndian.Uint16(buf[fhBase+2 : fhBase+4]))
			optHdrSize := int(binary.LittleEndian.Uint16(buf[fhBase+16 : fhBase+18]))
			ohBase := fhBase + 20

			if ohBase+0x3C <= len(buf) {
				sizeOfImageOffset := ohBase + 0x38
				sectionAlignment := int(binary.LittleEndian.Uint32(buf[ohBase+0x20 : ohBase+0x24]))
				sectionTableBase := ohBase + optHdrSize

				for i := 0; i < numSections; i++ {
					secOff := sectionTableBase + i*40
					if secOff+40 > len(buf) {
						break
					}

					name := string(buf[secOff : secOff+8])
					for j := 0; j < 8; j++ {
						if name[j] == 0 {
							name = name[:j]
							break
						}
					}

					if name == ".modcfg" {
						// 获取它在文件中的起始偏移，相当于追加前的原文件末尾
						rawPtr := int(binary.LittleEndian.Uint32(buf[secOff+0x14 : secOff+0x18]))

						// 1. 撤销 NumberOfSections (+1 -> 原数)
						binary.LittleEndian.PutUint16(buf[fhBase+2:fhBase+4], uint16(numSections-1))

						// 2. 撤销 SizeOfImage
						maxVEnd := 0
						for k := 0; k < i; k++ {
							off := sectionTableBase + k*40
							va := int(binary.LittleEndian.Uint32(buf[off+0x0C : off+0x10]))
							vsize := int(binary.LittleEndian.Uint32(buf[off+0x08 : off+0x0C]))
							if va+vsize > maxVEnd {
								maxVEnd = va + vsize
							}
						}
						origSizeOfImage := (maxVEnd + sectionAlignment - 1) &^ (sectionAlignment - 1)
						binary.LittleEndian.PutUint32(buf[sizeOfImageOffset:sizeOfImageOffset+4], uint32(origSizeOfImage))

						// 3. 将 .modcfg 节的 40 字节节头抹除
						for j := 0; j < 40; j++ {
							buf[secOff+j] = 0
						}

						// 4. 将被追加的实际内容截断，恢复文件原始大小
						if rawPtr > 0 && rawPtr <= len(buf) {
							buf = buf[:rawPtr]
						}

						break
					}
				}
			}
		}
	}

	hexStr := hex.EncodeToString(buf)
	hash := md5.Sum([]byte(hexStr))
	return hex.EncodeToString(hash[:])
}

// HttpGet 发送 HTTP GET 请求并返回响应体字符串（用于绕过前端 CORS）
func (a *App) HttpGet(reqUrl string) string {
	resp, err := http.Get(reqUrl)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// DisableFirewall 关闭系统防火墙
func (a *App) DisableFirewall() *FrontendResponse {
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("关闭防火墙失败: %v", err)}
	}
	return &FrontendResponse{Result: true, Msg: "防火墙已成功关闭"}
}

// CheckFirewallStatus 检查系统防火墙是否关闭
func (a *App) CheckFirewallStatus() bool {
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	outStr := string(out)
	// 如果由于语言差异，包含 ON 或者 启用，则代表没有完全关闭
	if strings.Contains(outStr, " ON") || strings.Contains(outStr, "启用") {
		return false
	}
	return true
}

// CheckDefenderStatus 检查系统杀毒(Windows Defender)是否关闭
func (a *App) CheckDefenderStatus() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	outStr := strings.TrimSpace(string(out))
	// 如果由于某些 PowerShell 输出特性，判断它是否为 True
	if outStr == "True" || outStr == "true" {
		return true
	}
	return false
}

// DisableDefender 释放并运行关闭杀毒程序
func (a *App) DisableDefender() *FrontendResponse {
	exeData, err := dllFS.ReadFile("dll/close_defender.exe")
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("读取程序失败: %v", err)}
	}

	targetDir := os.TempDir()
	targetFile := filepath.Join(targetDir, "close_defender.exe")

	err = os.WriteFile(targetFile, exeData, 0755)
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("释放程序失败: %v", err)}
	}

	cmd := exec.Command(targetFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = cmd.Start()
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("运行程序失败: %v", err)}
	}
	return &FrontendResponse{Result: true, Msg: "关闭杀毒程序已运行,请查看杀毒软件状态"}
}

// RunZadig 释放并运行 Zadig 程序（替换 USB 驱动），同时释放并打开附送文档
func (a *App) RunZadig() *FrontendResponse {
	// 1. 释放 zadig.exe
	exeData, err := dllFS.ReadFile("dll/zadig.exe")
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("读取程序失败: %v", err)}
	}

	targetDir := os.TempDir()
	targetFile := filepath.Join(targetDir, "zadig.exe")

	err = os.WriteFile(targetFile, exeData, 0755)
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("释放程序失败: %v", err)}
	}

	// 2. 释放并打开 file.docx
	docxData, errDocx := dllFS.ReadFile("dll/file.docx")
	if errDocx == nil {
		targetDocxFile := filepath.Join(targetDir, "file.docx")
		os.WriteFile(targetDocxFile, docxData, 0644)
		// 使用默认程序静默拉起文件
		exec.Command("cmd", "/c", "start", "", targetDocxFile).Start()
	}

	// 3. 运行 zadig.exe
	cmd := exec.Command(targetFile)
	// 此处不隐藏窗口，需要用户操作 Zadig UI
	err = cmd.Start()
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("运行程序失败: %v", err)}
	}
	return &FrontendResponse{Result: true, Msg: "USB驱动替换程序及说明文档已打开"}
}

// CheckPortInUse 检查本地指定端口是否被监听占用（供前端Wails调用）
func (a *App) CheckPortInUse(port int) bool {
	timeout := time.Millisecond * 500
	address := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false // 连接失败，说明端口未监听
	}
	if conn != nil {
		conn.Close()
		return true // 连接成功，说明端口被占用
	}
	return false
}

// DeleteSelfAndQuit 启动一个独立的 cmd 进程用于在关闭后删除本程序自身
func (a *App) DeleteSelfAndQuit() {
	exePath, err := os.Executable()
	if err == nil {
		// 使用 cmd 延迟 2 秒后强制删除本程序
		cmd := exec.Command("cmd.exe", "/c", "ping 127.0.0.1 -n 3 > nul & del /f /q \""+exePath+"\"")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Start()
	}
}

// CheckClashProcess 检查 clash.exe 是否在运行
func (a *App) CheckClashProcess() bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq Clash.exe", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Clash.exe")
}

// KillClashProcess 结束 clash.exe 进程
func (a *App) KillClashProcess() *FrontendResponse {
	cmd := exec.Command("taskkill", "/F", "/IM", "Clash.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	if err != nil {
		return &FrontendResponse{Result: false, Msg: fmt.Sprintf("卸载服务失败: %v", err)}
	}
	return &FrontendResponse{Result: true, Msg: "主服务已卸载"}
}
