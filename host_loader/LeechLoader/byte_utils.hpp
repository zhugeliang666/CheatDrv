
#include "common.h"


namespace bytes {

    // -------- 基础：std::string ↔ std::vector<unsigned char> --------
    inline std::vector<unsigned char> to_bytes(std::string_view s) {
        return std::vector<unsigned char>(s.begin(), s.end());
    }
    inline void to_bytes(std::string_view s, std::vector<unsigned char>& out) {
        out.assign(s.begin(), s.end());
    }


    inline std::string to_string(const std::vector<unsigned char>& v) {
        // 不做编码转换——按原始字节直接构造
        return std::string(reinterpret_cast<const char*>(v.data()), v.size());
    }

    // 可选：保留结尾 '\0'
    inline std::vector<unsigned char> to_bytes_cstr(std::string_view s) {
        std::vector<unsigned char> v(s.begin(), s.end());
        v.push_back('\0');
        return v;
    }


    inline std::wstring whex_encode(const std::vector<unsigned char>& v, bool uppercase = true)
    {
        static const wchar_t* LUT_UP = L"0123456789ABCDEF";
        static const wchar_t* LUT_LO = L"0123456789abcdef";
        const wchar_t* LUT = uppercase ? LUT_UP : LUT_LO;

        std::wstring out;
        out.reserve(v.size() * 2);

        for (unsigned char b : v) {
            out.push_back(LUT[b >> 4]);    // 高 4 bit
            out.push_back(LUT[b & 0x0F]);  // 低 4 bit
        }
        return out;
    }

    // -------- Hex 编解码（大小写均可输入，输出默认大写） --------
    inline std::string hex_encode(const std::vector<unsigned char>& v, bool uppercase = true) {
        static const char* LUT_UP = "0123456789ABCDEF";
        static const char* LUT_LO = "0123456789abcdef";
        const char* LUT = uppercase ? LUT_UP : LUT_LO;
        std::string out; out.reserve(v.size() * 2);
        for (unsigned char b : v) {
            out.push_back(LUT[b >> 4]);
            out.push_back(LUT[b & 0x0F]);
        }
        return out;
    }
    inline unsigned char _hex_val(char c) {
        if (c >= '0' && c <= '9') return (unsigned char)(c - '0');
        if (c >= 'a' && c <= 'f') return (unsigned char)(10 + c - 'a');
        if (c >= 'A' && c <= 'F') return (unsigned char)(10 + c - 'A');
        throw std::invalid_argument("hex_decode: invalid hex digit");
    }
    inline std::vector<unsigned char> hex_decode(std::string_view hex) {
        // 去空白（常见输入可能夹带空格/换行）
        std::string s; s.reserve(hex.size());
        for (char c : hex) if (!isspace((unsigned char)c)) s.push_back(c);
        if (s.size() % 2) throw std::invalid_argument("hex_decode: length must be even");
        std::vector<unsigned char> out; out.reserve(s.size() / 2);
        for (size_t i = 0; i < s.size(); i += 2) {
            unsigned char hi = _hex_val(s[i]);
            unsigned char lo = _hex_val(s[i + 1]);
            out.push_back(static_cast<unsigned char>((hi << 4) | lo));
        }
        return out;
    }

    // -------- Base64 编解码（RFC 4648，带 '=' 填充） --------
    inline std::string base64_encode(const std::vector<unsigned char>& v) {
        static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; out.reserve((v.size() + 2) / 3 * 4);
        size_t i = 0;
        while (i + 3 <= v.size()) {
            uint32_t n = (v[i] << 16) | (v[i + 1] << 8) | (v[i + 2]);
            out.push_back(T[(n >> 18) & 0x3F]);
            out.push_back(T[(n >> 12) & 0x3F]);
            out.push_back(T[(n >> 6) & 0x3F]);
            out.push_back(T[(n) & 0x3F]);
            i += 3;
        }
        if (i < v.size()) {
            uint32_t n = (v[i] << 16);
            if (i + 1 < v.size()) n |= (v[i + 1] << 8);
            out.push_back(T[(n >> 18) & 0x3F]);
            out.push_back(T[(n >> 12) & 0x3F]);
            if (i + 1 < v.size()) {
                out.push_back(T[(n >> 6) & 0x3F]);
                out.push_back('=');
            }
            else {
                out.push_back('=');
                out.push_back('=');
            }
        }
        return out;
    }
    inline std::vector<unsigned char> base64_decode(std::string_view s) {
        auto val = [](int c)->int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
            };
        std::vector<unsigned char> out;
        int valb = -8; int accum = 0;
        for (unsigned char c : s) {
            if (isspace(c)) continue;
            if (c == '=') break;
            int v = val(c);
            if (v < 0) throw std::invalid_argument("base64_decode: invalid char");
            accum = (accum << 6) | v;
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<unsigned char>((accum >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    // -------- UTF-8 ↔ 宽字符（Windows 优先用 WinAPI，其他平台用 codecvt 兜底）--------
#ifdef _WIN32
    inline std::wstring utf8_to_wide(std::string_view utf8) {
        if (utf8.empty()) return L"";
        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
        std::wstring w(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), w.data(), wlen);
        return w;
    }
    inline std::string wide_to_utf8(std::wstring_view w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), len, nullptr, nullptr);
        return s;
    }
#else
    inline std::wstring utf8_to_wide(std::string_view utf8) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.from_bytes(utf8.data(), utf8.data() + utf8.size());
    }
    inline std::string wide_to_utf8(std::wstring_view w) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(w.data(), w.data() + w.size());
    }
#endif

    // -------- 便捷封装：UTF-8 字符串 ↔ 字节 --------

    inline std::string bytes_to_utf8(const std::vector<unsigned char>& v) {
        return to_string(v);
    }

    static inline std::wstring Utf8ToW(const uint8_t* p, size_t n) {
        if (!p || n == 0) return L"";
        int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)p, (int)n, nullptr, 0);
        if (wlen <= 0) return L""; // 无法按 UTF-8 解码就返回空
        std::wstring w; w.resize(wlen);
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)p, (int)n, w.data(), wlen);
        return w;
    }



    inline std::string StrToHex(const std::string& input) {
        static const char* const lut = "0123456789ABCDEF";
        std::string output;
        output.reserve(input.size() * 2);
        for (unsigned char c : input) {
            output.push_back(lut[c >> 4]);      // 高 4 bit
            output.push_back(lut[c & 0x0F]);    // 低 4 bit
        }
        return output;
    }


    // 去掉 UTF-8 字符串首尾空白（Unicode 空白都支持）
    static inline std::string strTrimUtf8(std::string s) {
        // 先把 UTF-8 转成宽字串
        std::wstring w = utf8_to_wide(s);

        // 可选：去 BOM（U+FEFF）
        if (!w.empty() && w.front() == 0xFEFF) w.erase(w.begin());

        // 左 trim
        size_t i = 0;
        while (i < w.size() && iswspace(w[i])) ++i;
        // 右 trim
        size_t j = w.size();
        while (j > i && iswspace(w[j - 1])) --j;

        w = (i < j) ? w.substr(i, j - i) : L"";

        // 转回 UTF-8
        return wide_to_utf8(w);
    }



    // 16进制转换为字符串
    inline  std::string HexToStr(const std::string& hex) {
        if (hex.size() % 2 != 0)
            throw std::invalid_argument("Hex string length must be even");

        auto hexVal = [](char c) -> uint8_t {
            if ('0' <= c && c <= '9') return c - '0';
            if ('a' <= c && c <= 'f') return 10 + (c - 'a');
            if ('A' <= c && c <= 'F') return 10 + (c - 'A');
            throw std::invalid_argument("Invalid hex digit");
            };

        std::string out;
        out.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.size(); i += 2)
        {
            uint8_t hi = hexVal(hex[i]);
            uint8_t lo = hexVal(hex[i + 1]);
            out.push_back(static_cast<char>((hi << 4) | lo));
        }
        return out;
    }
} // namespace bytes