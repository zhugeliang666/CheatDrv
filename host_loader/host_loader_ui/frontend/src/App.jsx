import React from 'react';
import { getBrandConfig } from './config/brandConfig';
import AppDefault from './AppDefault';
import AppLiejiu from './AppLiejiu';

function App() {
    // 根据环境选取不同的配置标识
    const brand = "liejiu";

    // 目前支持 liejiu 显示暗黑现代版，其余默认全套应用 WN DEPLOYER 新版皮肤
    if (brand === 'liejiu') {
        return <AppLiejiu />;
    }

    return <AppDefault />;
}

export default App;
