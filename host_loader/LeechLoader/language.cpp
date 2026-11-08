#include "common.h"
#include "language.h"
#include <string>

std::wstring strTowStr(const std::string &utf8);

LanguageManager::LanguageManager()
{
    currentLanguage = DetectLanguage();
    InitializeTranslations();
}

// 检测语言
Language LanguageManager::DetectLanguage()
{
    return Language::English;
}

void LanguageManager::InitializeTranslations()
{
    // 运行环境与生命周期
    translations["system.init_success"] = {"运行环境初始化就绪", "Environment initialized successfully"};
    translations["system.found_local_ip"] = {"节点通信地址: ", "Node address: "};
    translations["system.preparing_close"] = {"任务已接管，环境安全退出", "Handover completed, terminating host safely"};
    translations["game.injection_success"] = {"协同服务接管成功，宿主环境准备退出", "Service initialized successfully, preparing to exit"};

    // 控制端点与设备发现
    translations["device.waiting_discovery"] = {"正在等待控制端点接入...", "Waiting for endpoint connection..."};
    translations["device.secondary_prefix"] = {"协同端点 [", "Endpoint ["};
    translations["device.discovered_suffix"] = {"] 已接入，正在同步会话...", "] connected, synchronizing session..."};
    translations["device.scan_port_fail"] = {"通信信道分配异常，请重试", "Channel allocation failed, please retry"};

    // 通信与网络服务
    translations["service.create_failed_firewall"] = {"通信信道建立失败，请检查网络策略或端口占用", "Failed to establish communication channel, check network policy"};
    translations["transfer.header_failed"] = {"通信协议同步失败", "Protocol synchronization failed"};
    translations["transfer.content_failed"] = {"数据传输未完成，通信中断", "Data transmission incomplete, connection reset"};
    translations["transfer.unknown_exception"] = {"通信过程发生异常", "Communication exception occurred"};

    // 部署与载荷调度
    translations["deploy.host_success"] = {"服务端点就绪，等待下发协同载荷...", "Service endpoint ready, awaiting payload..."};
    translations["deploy.program_data"] = {"核心运行时组件同步就绪", "Runtime component synchronized"};
    translations["deploy.dual_data1"] = {"底层协同载荷已接收就绪", "Underlying payload received successfully"};
    translations["deploy.dual_data2"] = {"辅助协同模块已就绪", "Auxiliary module synchronized"};
    translations["deploy.failed"] = {"驱动部署失败，保持运行状态以便排查", "Driver deployment failed, host loader preserved for diagnostics"};

    // 鉴权与参数校验
    translations["auth.data_error"] = {"会话凭据校验未通过，请重新同步", "Session validation failed, please re-synchronize"};
    translations["auth.data_error2"] = {"载荷数据完整性校验不一致，请重试", "Payload integrity verification failed, please retry"};
    translations["auth.connect_mode_fail"] = {"通道模式不兼容，请重新导出配置", "Channel mode mismatch, please re-export configuration"};
    translations["auth.usb_discover_fail"] = {"未检测到协同硬件，请检查硬件连接与接口状态", "Hardware device not detected, check connection status"};
    translations["auth.deployed_success"] = {"协同凭据配置生效", "Credentials validated and applied"};

    // 权限与服务管控
    translations["error.run_as_admin"] = {"需要以系统管理员身份运行本程序", "Administrative privileges are required to run this program"};
    translations["error.user_declined_elevation"] = {"请求提升执行权限被取消", "Privilege elevation was declined"};
    translations["config.pe_header_no_found_config"] = {"节点元数据缺失，请重新生成并同步", "Node metadata missing, please re-generate and sync"};
    translations["error.program_exception"] = {"执行环境遇到未预期状况，请重新启动", "Unexpected runtime condition, please restart"};
    translations["service.host_running_ask_uninstall"] = {"已存在活跃的协同服务实例，是否注销并清理？(Y/N)", "Active service instance already running. Terminate and cleanup? (Y/N)"};
    translations["service.host_uninstalled"] = {"协同服务已安全注销", "Service safely deregistered"};
}

LanguageManager &LanguageManager::GetInstance()
{
    static LanguageManager instance;
    return instance;
}

std::string g_key;

bool IsStringUTF8(const std::string &str)
{
    int num_bytes = 0;
    for (unsigned char c : str)
    {
        if (num_bytes == 0)
        {
            if ((c & 0x80) != 0)
            {
                if ((c & 0xE0) == 0xC0)
                    num_bytes = 1;
                else if ((c & 0xF0) == 0xE0)
                    num_bytes = 2;
                else if ((c & 0xF8) == 0xF0)
                    num_bytes = 3;
                else
                {
                    return false;
                }
            }
        }
        else
        {
            if ((c & 0xC0) != 0x80)
            {
                return false;
            }
            num_bytes--;
        }
    }
    return (num_bytes == 0);
}

std::string cToUTF8(const std::string &str)
{
    if (str.empty())
    {
        return "";
    }

    // 如果字符串本身就是 UTF-8 格式，直接返回
    if (IsStringUTF8(str))
    {
        return str;
    }

    // 否则说明是 GBK / ANSI 格式，执行转 UTF-8 转换
    int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
    if (len <= 0)
    {
        return str;
    }

    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wstr[0], len);

    int u8len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    if (u8len <= 0)
    {
        return str;
    }

    std::string strUTF8(u8len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &strUTF8[0], u8len, NULL, NULL);

    if (!strUTF8.empty() && strUTF8.back() == '\0')
        strUTF8.pop_back();

    return strUTF8;
}

const char *LanguageManager::GetChar(const std::string &key)
{
    auto it = translations.find(key);
    if (it != translations.end())
    {
        std::string resultStr;
        if (currentLanguage == Language::Chinese)
        {
            resultStr = it->second.chinese;
        }
        else
        {
            resultStr = it->second.english;
        }
        std::string utf8Str = cToUTF8(resultStr);
        g_key = utf8Str;
        return g_key.c_str();
    }
    // 如果找不到键，返回键本身作为fallback
    g_key = key;
    return g_key.c_str();
}

std::string LanguageManager::GetString(const std::string &key)
{
    auto it = translations.find(key);
    if (it != translations.end())
    {
        std::string resultStr;
        if (currentLanguage == Language::Chinese)
        {
            resultStr = it->second.chinese;
        }
        else
        {
            resultStr = it->second.english;
        }
        std::string utf8Str = cToUTF8(resultStr);
        return utf8Str;
    }
    // 如果找不到键，返回键本身作为fallback
    return key;
}

Language LanguageManager::GetCurrentLanguage() const
{
    Language lang = currentLanguage;
    return lang;
}

void LanguageManager::SetLanguage(Language lang)
{
    currentLanguage = lang;
}
