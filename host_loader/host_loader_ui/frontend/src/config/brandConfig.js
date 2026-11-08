export const brandConfig = {
    default: {
        title: "主机文件",
        shellcodeType: "host_loader",
        version: "v1.0.0",
        logoLetter: "W",
        logoColor: "#6366F1"
    },
    liejiu: {
        title: "主机文件",
        shellcodeType: "host_loader",
        version: "v1.0.0",
        logoLetter: "L",
        logoColor: "#10B981"
    }
};

export const getBrandConfig = () => {
    // import.meta.env 可能在某些环境中不存在，因此提供容错处理
    const brand = (import.meta && import.meta.env && import.meta.env.VITE_APP_BRAND) || 'default';
    return brandConfig[brand] || brandConfig.default;
};
