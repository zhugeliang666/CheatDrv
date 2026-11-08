package main

import (
	"embed"
	"syscall"
	"unsafe"

	"host_loader_ui/backend"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	user32          = syscall.NewLazyDLL("user32.dll")
	procCreateMutex = kernel32.NewProc("CreateMutexW")
	procMessageBox  = user32.NewProc("MessageBoxW")
)

// checkSingleInstance 检查是否已有实例在运行
func checkSingleInstance() bool {
	mutexName, _ := syscall.UTF16PtrFromString("Global\\HostLoaderUI_SingleInstance_Mutex")

	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(mutexName)),
	)

	if ret == 0 {
		return false
	}

	// ERROR_ALREADY_EXISTS = 183
	if err != nil && err.(syscall.Errno) == 183 {
		return false
	}

	return true
}

// showMessageBox 显示消息框
func showMessageBox(title, message string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	procMessageBox.Call(
		0,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0x00000030, // MB_ICONWARNING | MB_OK
	)
}

func main() {
	// 检查单实例
	if !checkSingleInstance() {
		showMessageBox("警告", "程序已在运行中，不能重复启动！")
		return
	}

	// 创建应用实例
	app := backend.NewApp()

	// 创建应用选项
	err := wails.Run(&options.App{
		Title:  "OneDrive",
		Width:  1024,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 20, G: 20, B: 30, A: 0},
		OnStartup:        app.Startup,
		OnShutdown:       app.Shutdown,
		Frameless:        true, // 无边框窗口
		DisableResize:    true, // 禁止调整窗口大小
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
