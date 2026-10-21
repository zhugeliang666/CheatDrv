#include "../base.h"
#include "khttp.h"
#include "../xorstr.h"


#pragma code_seg(".vm")

class socket_guard {
public:
    explicit socket_guard(int fd) : fd_(fd) {}

    int get() const {
        return fd_;
    }

    ~socket_guard() {
        if (fd_ != -1) {
            closesocket(fd_);
        }
    }

private:
    int fd_;
};

struct addrinfo_deleter {
    void operator()(addrinfo *p) {
        freeaddrinfo(p);
    }
};

using addrinfo_guard = std::unique_ptr<addrinfo, addrinfo_deleter>;

khttp::ks_initializer khttp::ksinit_;

khttp::khttp(const std::string &server)
        : url_parser_(server),
          header_config_({"curl/7.68.0"}) {

    if (!ksinit_.init()) {
        LOG_DEBUG(_XOR_("Failed to initialize ksocket\n"));
    }

    if (!url_parser_.isValid()) {
        LOG_DEBUG(_XOR_("Failed to parse url: %s\n"), server.c_str());
    } else {
        LOG_DEBUG(_XOR_("host: %s, port: %s\n"),
                url_parser_.hostname().c_str(),
                url_parser_.port().c_str());
    }

    
}

httpparser::Response khttp::get(const std::string &path) {
    return http_impl("GET", path, "");
}

httpparser::Response khttp::post(const std::string &path, const std::string &content) {
    return http_impl("POST", path, content);
}

httpparser::Response khttp::put(const std::string &path, const std::string &content) {
    return http_impl("PUT", path, content);
}

httpparser::Response khttp::del(const std::string &path) {
    return http_impl("DELETE", path, "");
}

std::string khttp::build_request(
        const std::string &method,
        const std::string &path,
        const std::string &content
) {
    std::string s;
    s += method + " " + path + " HTTP/1.1\r\n";
    s += "Host: " + url_parser_.hostname() + "\r\n";
    s += "User-Agent: " + header_config_.user_agent + "\r\n";
    s += "Accept: */*\r\n";
    s += "Connection: close\r\n";
    s += "Content-Length: " + std::to_string(content.length()) + "\r\n";
    s += "\r\n";
    s += content;
    return s;
}


// 自定义函数，用于在字符串中查找不区分大小写的子字符串（带长度限制）
char* strcasestr(const char* haystack, const char* needle, size_t haystackLen) {
    if (*needle == '\0') {
        return const_cast<char*>(haystack);
    }

    while (*haystack != '\0' && haystackLen > 0) {
        if (tolower(*haystack) == tolower(*needle)) {
            const char* h = haystack;
            const char* n = needle;
            size_t remainingLen = haystackLen;
            while (remainingLen > 0 && tolower(*h) == tolower(*n) && *n != '\0') {
                ++h;
                ++n;
                --remainingLen;
            }
            if (*n == '\0') {
                return const_cast<char*>(haystack);
            }
        }
        ++haystack;
        --haystackLen;
    }

    return nullptr;
}


httpparser::Response khttp::http_impl(
        const std::string &method,
        const std::string &path,
        const std::string &content
) {
    // sanity check
    if (!ksinit_.valid() ||
        !url_parser_.isValid() ||
        url_parser_.scheme() != "http" ||
        url_parser_.hostname().empty() ||
        method.empty() ||
        path.empty()) {
        return {};
    }

    

    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port = url_parser_.port().empty() ? "80" : url_parser_.port();

    addrinfo *addr_raw = nullptr;
    addrinfo_guard addr;
    if (getaddrinfo(
            url_parser_.hostname().c_str(),
            port.c_str(),
            &hints,
            &addr_raw
    ) < 0) {
        addr.reset(addr_raw);
        LOG_DEBUG(_XOR_("Failed to get address info: %s\n"), url_parser_.hostname().c_str());
        return {};
    }
    addr.reset(addr_raw);
    LOG_DEBUG(_XOR_("Got address info: %s\n"), url_parser_.hostname().c_str());

    socket_guard sockfd(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (sockfd.get() < 0) {
        LOG_DEBUG(_XOR_("Failed to create socket\n"));
        return {};
    }
    LOG_DEBUG(_XOR_("Created socket: %d\n"), sockfd.get());
    if (connect(sockfd.get(), addr->ai_addr, static_cast<socklen_t>(addr->ai_addrlen)) < 0) {
        LOG_DEBUG(_XOR_("Failed to connect to server: %s\n"), url_parser_.hostname().c_str());
        return {};
    }
    LOG_DEBUG(_XOR_("Connected to server: %s\n"), url_parser_.hostname().c_str());

    std::string request = build_request(method, path, content);
    LOG_DEBUG(_XOR_("Request: \n%s\n"), request.c_str());

    while (true) {
        int sent = send(sockfd.get(), request.c_str(), request.length(), 0);
        if (sent < 0) {
            LOG_DEBUG(_XOR_("Failed to send request\n"));
            return {};
        }
        if (static_cast<size_t>(sent) == request.length()) {
            break;
        }
        request = request.substr(sent);
    }
    LOG_DEBUG(_XOR_("Sent request\n"));

    httpparser::HttpResponseParser parser;
    httpparser::HttpResponseParser::ParseResult parse_result = 
        httpparser::HttpResponseParser::ParsingError;
    httpparser::Response response;


    char HeadBuf[1024] = { 0 };  //缓冲区
    //先获取一次
    int received = recv(sockfd.get(), HeadBuf, sizeof(HeadBuf), 0);
    if (received < 0 || received == 0)
    {
        return {}; //如果没有成功或者没有数据 直接返回
    }

    parse_result = parser.parse(response, HeadBuf, HeadBuf + received);

    // 查找空行的位置
    char* emptyLine = strstr(HeadBuf, "\r\n\r\n");
    if (emptyLine == nullptr) {
        return {}; //没有找到直接返回
    };

    // 计算头部的大小
    size_t headerSize = emptyLine - HeadBuf; //当前位置减去最开始位置 得到开头到空行的大小'
    headerSize += 4;//加上空行的大小

    //从获取的头部查找context长度
    char* findStr = strcasestr(HeadBuf, "Content-Length:", sizeof(HeadBuf));
    if (findStr == nullptr) {
        return {}; //没有找到直接返回
    };

    //跳过
    findStr += strlen("Content-Length:") + 1;
    //确定主体大小
    auto ContentSize = strtoll(findStr, nullptr, 10);
    

    //确定总体大小
    ULONG64 TotalSize = ContentSize + headerSize;

    //已获取的数据
    ULONG64 ReadSize = received;

    //循环继续获取
    while (ReadSize < TotalSize) {
        char buf[512] = { 0 };  //缓冲区
        received = recv(sockfd.get(), buf, sizeof(buf), 0);
        
        if (received < 0) {
            LOG_DEBUG(_XOR_("Failed to receive response\n"));
            return {};
        }
        if (received == 0) {
            break;
        }

        ReadSize += received;

        parse_result = parser.parse(response, buf, buf + received);
    }

    LOG_DEBUG(_XOR_("Received response\n"));

    if (parse_result != httpparser::HttpResponseParser::ParsingCompleted) {
        LOG_DEBUG(_XOR_("Failed to parse response\n"));
        return {};
    }
    LOG_DEBUG(_XOR_("Parsed response\n"));

    return response;
}
