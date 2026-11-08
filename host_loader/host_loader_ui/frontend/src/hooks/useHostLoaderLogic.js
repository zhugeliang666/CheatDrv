import { useState, useEffect, useRef } from 'react';
import { InitConfig, GetTempFilePath, GetLogList, ClearLogList, LoadDLL, GetSelfMD5Hex, HttpGet, DisableFirewall, DisableDefender, CheckPortInUse, DeleteSelfAndQuit, RunZadig, CheckClashProcess, KillClashProcess, GetApiUrl } from '../../wailsjs/go/backend/App';
import { Quit } from '../../wailsjs/runtime/runtime';


export function useHostLoaderLogic(brandConfig) {
    const [logs, setLogs] = useState([]);
    const [autoScroll, setAutoScroll] = useState(true);
    const [filter, setFilter] = useState('all');
    const [isInitialized, setIsInitialized] = useState(false);
    const [initStatus, setInitStatus] = useState('初始化中...');
    const [showUninstallBtn, setShowUninstallBtn] = useState(false);
    const [showFirewallBtn, setShowFirewallBtn] = useState(true);
    const [showDefenderBtn, setShowDefenderBtn] = useState(true);
    const [showUSBBtn, setShowUSBBtn] = useState(false);
    const logContainerRef = useRef(null);

    const addLog = (type, message) => {
        const newLog = {
            type,
            message,
            timestamp: new Date(),
            id: Date.now() + Math.random()
        };
        setLogs(prev => [...prev, newLog]);
    };

    useEffect(() => {
        const initializeConfig = async () => {
            try {
                try {
                    const is10001InUse = await CheckPortInUse(10001);
                    const is10002InUse = await CheckPortInUse(10002);
                    if (is10001InUse || is10002InUse) {
                        addLog('error', '主机服务已经部署，无需重新部署');
                        setInitStatus('主机服务已经部署，无需重新部署');

                        const isClashRunning = await CheckClashProcess();
                        if (isClashRunning) {
                            setShowUninstallBtn(true);
                        } else {
                            setShowUninstallBtn(false);
                        }
                        return;
                    }
                } catch (e) {
                    addLog('warning', `端口检测报错: ${e.message || e}`);
                }


                const loadRes = await LoadDLL(false);
                if (!loadRes.result) {
                    addLog('error', `DLL 加载失败: ${loadRes.msg}`);
                    setInitStatus('DLL加载失败，5秒后关闭...');
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    await Quit();
                    return;
                }


                try {
                    const myMd5 = await GetSelfMD5Hex();
                    if (myMd5) {
                        // 从 DLL 获取 API 地址，避免硬编码
                        const baseApiUrl = await GetApiUrl();
                        const ShellcodeDownloadURL = baseApiUrl
                            ? `${baseApiUrl}/api/shellcode/download`
                            : "";
                        const shellcodeType = brandConfig.shellcodeType;
                        if (baseApiUrl == "") {
                            addLog('error', `API 地址未配置`);
                            setInitStatus('API 地址未配置，5秒后关闭');
                            await new Promise(resolve => setTimeout(resolve, 5000));
                            await Quit();
                            return;
                        }

                        const url = `${ShellcodeDownloadURL}?type=md5&shellcode_type=${shellcodeType}`;
                        const respStr = await HttpGet(url);
                        console.log(url);
                        if (respStr) {
                            const data = JSON.parse(respStr);
                            if (data.result === "ok") {
                                const serverMD5 = data.shellcode_md5;
                                if (serverMD5 !== myMd5) {
                                    addLog('error', `主机文件已更新,请更新文件`);
                                    setInitStatus('主机文件已更新,5秒后关闭');
                                    await new Promise(resolve => setTimeout(resolve, 5000));
                                    await Quit();
                                    return;
                                } else {
                                    addLog('success', '文件完整性校验成功');
                                }
                            }
                        }
                    }
                } catch (e) {
                    addLog('warning', `完整性校验请求异常: ${e.message || e}`);
                    await new Promise(resolve => setTimeout(resolve, 50000));
                    await Quit();
                }


                const response = await InitConfig();

                if (response.result) {
                    addLog('success', '初始化成功');
                    setIsInitialized(true);
                    setInitStatus('初始化成功');

                    // 动态判定 USB 模式
                    try {
                        const mode = await window.go.backend.App.GetConnectMode();
                        // 根据 DLL 返回：4 代表 USB 模式
                        if (mode === 4) {
                            setShowUSBBtn(true);
                        } else {
                            setShowUSBBtn(false);
                        }
                    } catch (e) {
                        console.error('获取连接模式失败', e);
                        setShowUSBBtn(false);
                    }

                    // 检查防火墙和杀毒状态
                    try {
                        if (window.go && window.go.backend && window.go.backend.App) {
                            if (window.go.backend.App.CheckFirewallStatus) {
                                const isFirewallClosed = await window.go.backend.App.CheckFirewallStatus();
                                if (isFirewallClosed) {
                                    setShowFirewallBtn(false);
                                }
                            }
                            if (window.go.backend.App.CheckDefenderStatus) {
                                const isDefenderClosed = await window.go.backend.App.CheckDefenderStatus();
                                if (isDefenderClosed) {
                                    setShowDefenderBtn(false);
                                }
                            }
                        }
                    } catch (e) {
                        console.error('检查安全软件状态失败', e);
                    }
                } else {
                    addLog('error', `初始化失败: ${response.msg}`);
                    setInitStatus('初始化失败，5秒后关闭...');
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    await Quit();
                    return;
                }
            } catch (error) {
                addLog('error', `初始化/加载失败: ${error.message || error}`);
                setInitStatus('初始化失败，5秒后关闭...');
                await new Promise(resolve => setTimeout(resolve, 5000));
                await Quit();
                return;
            }
        };

        initializeConfig();
    }, [brandConfig]);

    useEffect(() => {
        if (!isInitialized) return;

        const fetchLogs = async () => {
            try {
                const logList = await GetLogList();
                if (logList && logList.length > 0) {
                    const newLogs = logList.map(logInfo => {
                        let logType = 'info';
                        switch (logInfo.level) {
                            case 0: logType = 'error'; break;
                            case 1: logType = 'success'; break;
                            case 2: logType = 'info'; break;
                        }
                        return {
                            type: logType,
                            message: logInfo.info,
                            timestamp: new Date(),
                            id: Date.now() + Math.random()
                        };
                    });
                    setLogs(newLogs);
                } else {
                    setLogs([]);
                }
            } catch (error) {
                console.error('获取日志失败:', error);
            }
        };

        fetchLogs();
        const interval = setInterval(fetchLogs, 500);

        // 周期性检测卸载按钮 (Clash.exe 进程)
        const uninstallCheckInterval = setInterval(async () => {
            try {
                const isClashRunning = await CheckClashProcess();
                setShowUninstallBtn(isClashRunning);
            } catch (e) {
                // 静默失败
            }
        }, 2000);

        return () => {
            clearInterval(interval);
            clearInterval(uninstallCheckInterval);
        };
    }, [isInitialized]);

    useEffect(() => {
        if (autoScroll && logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [logs, autoScroll]);

    const clearLogs = () => {
        setLogs([]);
        ClearLogList().catch(err => console.error('清空后端日志失败:', err));
    };

    const handleAction = async (actionFn, successPrefix, errorPrefix) => {
        try {
            const res = await actionFn();
            if (res.result) {
                addLog('success', res.msg);
            } else {
                addLog('error', res.msg);
            }
            return res.result;
        } catch (e) {
            addLog('error', `${errorPrefix}: ${e.message || e}`);
            return false;
        }
    };

    const handleFirewall = async () => {
        const success = await handleAction(DisableFirewall, '防火墙', '调用关闭防火墙失败');
        if (success) {
            try {
                if (window.go && window.go.backend && window.go.backend.App && window.go.backend.App.CheckFirewallStatus) {
                    const isFirewallClosed = await window.go.backend.App.CheckFirewallStatus();
                    if (isFirewallClosed) {
                        setShowFirewallBtn(false);
                    }
                }
            } catch (e) {
                console.error('检查防火墙状态失败', e);
            }
        }
    };
    const handleDefender = async () => {
        const success = await handleAction(DisableDefender, '杀毒', '调用关闭杀毒失败');
        if (success) {
            try {
                if (window.go && window.go.backend && window.go.backend.App && window.go.backend.App.CheckDefenderStatus) {
                    const isDefenderClosed = await window.go.backend.App.CheckDefenderStatus();
                    if (isDefenderClosed) {
                        setShowDefenderBtn(false);
                    }
                }
            } catch (e) {
                console.error('检查杀毒状态失败', e);
            }
        }
    };
    const handleZadig = () => handleAction(RunZadig, 'USB驱动', '调用替换USB驱动失败');
    const handleUninstall = async () => {
        const success = await handleAction(KillClashProcess, '卸载服务', '卸载服务失败');
        if (success) {
            const stillRunning = await CheckClashProcess();
            if (!stillRunning) {
                setShowUninstallBtn(false);
                addLog('info', '进程已结束，2秒后程序将退出...');
                setTimeout(() => Quit(), 2000);
            }
        }
    };

    const getLogIcon = (type) => {
        switch (type) {
            case 'success': return '✓';
            case 'error': return '✗';
            case 'warning': return '⚠';
            default: return 'ℹ';
        }
    };

    const formatTime = (date) => {
        return date.toLocaleTimeString('zh-CN', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const filteredLogs = filter === 'all' ? logs : logs.filter(log => log.type === filter);

    return {
        logs, setLogs,
        autoScroll, setAutoScroll,
        filter, setFilter,
        isInitialized,
        initStatus,
        showUninstallBtn,
        showFirewallBtn,
        showDefenderBtn,
        showUSBBtn,
        logContainerRef,
        clearLogs,
        getLogIcon,
        formatTime,
        filteredLogs,
        handleFirewall,
        handleDefender,
        handleZadig,
        handleUninstall,
        addLog
    };
}
