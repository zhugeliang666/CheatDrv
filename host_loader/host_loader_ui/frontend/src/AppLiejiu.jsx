import React from 'react';
import './AppLiejiu.css';
import { useHostLoaderLogic } from './hooks/useHostLoaderLogic';
import { Quit, WindowMinimise } from '../wailsjs/runtime/runtime';
import { getBrandConfig } from './config/brandConfig';

function AppLiejiu() {
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
        getLogIcon,
        formatTime,
        filteredLogs,
        handleFirewall,
        handleDefender,
        handleZadig,
        handleUninstall
    } = useHostLoaderLogic(brandConfig);

    const isSuccess = initStatus === '初始化成功';
    const hasError = initStatus.includes('失败') || initStatus.includes('已部署') || initStatus.includes('已更新');
    const statusClass = isSuccess ? 'active' : (hasError ? 'error' : '');

    return (
        <div id="AppLiejiu">
            <div className="lj-window">
                {/* Header */}
                <div className="lj-header">
                    <div className="lj-header-left">
                        <div className={`lj-status-dot ${statusClass}`}></div>
                        <span className="lj-header-title">STATUS</span>
                        <span className="lj-header-val">{initStatus === '初始化中...' ? 'CONNECTING...' : initStatus}</span>
                        <span style={{ marginLeft: 20, color: 'rgba(255,255,255,0.1)' }}>|</span>
                        <span className="lj-header-title" style={{ marginLeft: 20 }}>VERSION</span>
                        <span className="lj-header-val" style={{ color: '#D81A22' }}>{brandConfig.version}</span>
                    </div>
                    <div className="lj-window-controls">
                        <button className="lj-win-btn minimize" onClick={WindowMinimise}>
                            <span>─</span>
                        </button>
                        <button className="lj-win-btn close" onClick={Quit}>
                            <span>✕</span>
                        </button>
                    </div>
                </div>

                {/* Main */}
                <div className="lj-main">
                    <div className="lj-page-title">
                        <h1>系统环境部署</h1>
                        <div className="lj-page-subtitle">SYSTEM DEPLOYMENT</div>
                    </div>

                    <div className="lj-bento-grid">
                        {/* Card 1 - Always Show Security Environment */}
                        <div className="lj-bento-card">
                            <div className="lj-card-watermark">01</div>
                            <div className="lj-card-header">
                                <div className="lj-card-icon">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
                                </div>
                                <div className="lj-card-title">安全环境</div>
                            </div>
                            <div className="lj-card-actions">
                                {showFirewallBtn && <button className="lj-btn" onClick={handleFirewall}>防火墙</button>}
                                {showDefenderBtn && <button className="lj-btn" onClick={handleDefender}>杀毒</button>}
                                {!showFirewallBtn && !showDefenderBtn && <span style={{ fontSize: 10, color: '#10b981', fontWeight: '800' }}>✓ 已就绪</span>}
                            </div>
                        </div>

                        {/* Card 2 - USB Mode Only */}
                        {showUSBBtn && (
                            <div className="lj-bento-card">
                                <div className="lj-card-watermark">02</div>
                                <div className="lj-card-header">
                                    <div className="lj-card-icon">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z" /><line x1="3" y1="6" x2="21" y2="6" /><path d="M16 10a4 4 0 0 1-8 0" /></svg>
                                    </div>
                                    <div className="lj-card-title">外设重定向</div>
                                </div>
                                <div className="lj-card-actions">
                                    <button className="lj-btn lj-btn-primary" onClick={handleZadig}>替换USB驱动</button>
                                </div>
                            </div>
                        )}

                        {/* Card 3 - Services Running Only */}
                        {showUninstallBtn && (
                            <div className="lj-bento-card">
                                <div className="lj-card-watermark">03</div>
                                <div className="lj-card-header">
                                    <div className="lj-card-icon">
                                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                                    </div>
                                    <div className="lj-card-title">卸载管理</div>
                                </div>
                                <div className="lj-card-actions">
                                    <button className="lj-btn" style={{ borderColor: '#D81A22', color: '#D81A22' }} onClick={handleUninstall}>卸载服务</button>
                                </div>
                            </div>
                        )}
                    </div>

                    <div className="lj-logs-wrapper">
                        <div className="lj-logs-header">
                            <span className="lj-logs-title">CONSOLE LOG</span>
                            <span className="lj-logs-clear" onClick={clearLogs}>CLEAR</span>
                        </div>
                        <div className="lj-logs-container" ref={logContainerRef}>
                            {filteredLogs.map((log) => (
                                <div key={log.id} className={`lj-log-entry lj-log-${log.type}`}>
                                    <span className="lj-log-icon">{getLogIcon(log.type)}</span>
                                    <span className="lj-log-type">[{log.type.toUpperCase()}]</span>
                                    <span className="lj-log-msg">{log.message}</span>
                                </div>
                            ))}
                            {filteredLogs.length === 0 && (
                                <div className="lj-log-empty">
                                    <div className="lj-empty-icon">📋</div>
                                    <div className="lj-empty-text">暂无运行日志...</div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default AppLiejiu;
