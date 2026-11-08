import React from 'react';
import './AppDefault.css';
import { useHostLoaderLogic } from './hooks/useHostLoaderLogic';
import { Quit, WindowMinimise } from '../wailsjs/runtime/runtime';
import { getBrandConfig } from './config/brandConfig';

function AppDefault() {
    const brandConfig = getBrandConfig();
    const {
        logs,
        initStatus,
        showUninstallBtn,
        showFirewallBtn,
        showDefenderBtn,
        showUSBBtn,
        logContainerRef,
        clearLogs,
        formatTime,
        filteredLogs,
        handleFirewall,
        handleDefender,
        handleZadig,
        handleUninstall
    } = useHostLoaderLogic(brandConfig);

    // 计算状态点的颜色
    let statusClass = 'loading';
    if (initStatus === '初始化成功') statusClass = 'success';
    else if (initStatus.includes('失败') || initStatus.includes('已部署') || initStatus.includes('已更新')) statusClass = 'error';

    return (
        <div id="AppDefault">
            <div className="wn-window">
                {/* Header */}
                <div className="wn-header">
                    <div className="wn-title-group">
                        <div className="wn-logo" style={{ backgroundColor: brandConfig.logoColor }}>
                            {brandConfig.logoLetter || 'W'}
                        </div>
                        <div className="wn-title">WN DEPLOYER</div>
                        <div className="wn-version">{brandConfig.version}</div>
                    </div>
                    <div className="wn-window-controls">
                        <button className="wn-win-btn minimize" onClick={WindowMinimise}>─</button>
                        <button className="wn-win-btn close" onClick={Quit}>✕</button>
                    </div>
                </div>

                {/* Main Content */}
                <div className="wn-main">
                    <div className="wn-top-section">
                        {/* 左侧表单控件区 */}
                        <div className="wn-left-form">
                            <div className="wn-form-row">
                                <span className="wn-form-label">状态</span>
                                <div className="wn-status-indicator">
                                    <span className={`wn-status-dot ${statusClass}`}></span>
                                    <span>{initStatus === '初始化中...' ? 'Idle' : initStatus}</span>
                                </div>
                            </div>


                            <div className="wn-action-buttons">
                                {showFirewallBtn && (
                                    <button className="wn-btn wn-btn-primary" onClick={handleFirewall}>
                                        关闭防火墙
                                    </button>
                                )}
                                {showDefenderBtn && (
                                    <button className="wn-btn wn-btn-primary" onClick={handleDefender}>
                                        关闭杀毒
                                    </button>
                                )}
                                {showUSBBtn && (
                                    <button className="wn-btn wn-btn-secondary" onClick={handleZadig}>
                                        替换USB驱动
                                    </button>
                                )}
                                {showUninstallBtn && (
                                    <button className="wn-btn wn-btn-danger" onClick={handleUninstall}>
                                        卸载服务
                                    </button>
                                )}
                            </div>

                            <div className="wn-system-checks">
                                <div className="wn-check-item">✓ Administrator privileges OK</div>
                                <div className="wn-check-item">✓ Secure Boot is handled</div>
                                <div className="wn-check-item">✓ HVCI / Memory Integrity is standard</div>
                            </div>
                        </div>

                        {/* 右侧使用方法区 */}
                        <div className="wn-right-instructions">
                            <div className="wn-inst-title">使用方法</div>
                            <ul className="wn-inst-list">
                                <li><span>1.</span> 请务必先点击(无需重复操作) <b>关闭防火墙</b> 与 <b>关闭杀毒</b></li>
                                {showUSBBtn && <li><span>2.</span> 如果为USB模式 <b>则点击替换USB驱动</b> 来预备环境</li>}
                                <li><span>3.</span> 系统自动校验完整性并挂载专属驱动文件</li>
                                <li><span>4.</span> 等待 <b>状态</b> 显示为 <b>初始化成功</b></li>
                                <li><span>5.</span> 部署成功后，服务即处于自动监听就绪状态</li>
                                {showUninstallBtn && <li><span>6.</span> 如需还原系统环境，请点击 <b>卸载服务</b> 或通过系统重启</li>}
                                <li><span>7.</span> 本程序绿色无痕，退出不残留额外文件依赖</li>
                            </ul>
                        </div>
                    </div>

                    {/* 底部日志面板 */}
                    <div className="wn-bottom-console">
                        <div className="wn-console-title">
                            <span>CONSOLE</span>
                            <span
                                style={{ cursor: 'pointer', color: '#6366F1', fontWeight: '500' }}
                                onClick={clearLogs}
                            >
                                清空日志
                            </span>
                        </div>
                        <div className="wn-console-logs" ref={logContainerRef}>
                            {filteredLogs.map((log) => (
                                <div key={log.id} className={`wn-log-row ${log.type}`}>
                                    <span className="wn-log-time">[{formatTime(log.timestamp)}]</span>
                                    <span className="wn-log-msg">{log.message}</span>
                                </div>
                            ))}
                            {filteredLogs.length === 0 && (
                                <div className="wn-log-row">
                                    <span className="wn-log-time">[{formatTime(new Date())}]</span>
                                    <span className="wn-log-msg" style={{ color: '#10B981' }}>Ready - pending operations to start.</span>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default AppDefault;
