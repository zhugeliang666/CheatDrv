#pragma once
#include <cstdint>
#include <string>

#pragma pack(push, 1)

// ============================================================================
// 方案2: 纯二进制结构体协议 (Binary Frame Protocol)
// 彻底抹除明文伪 XML 标签字符串 (如 [TYPE], [CARDKEY] 等)，实现强类型与零内存拷贝
// ============================================================================

// 传统外层传输协议魔数
#define PACKET_MAGIC             0x414C5448   // 'HTLA'
#define PACKET_VERSION           1
#define FLAG_ENCRYPT             0x1

// 高性能结构化纯二进制帧魔数
#define HSTV_FRAME_MAGIC         0x56545348   // 'HSTV'

// 业务命令 ID 枚举 (HSTV_CMD_ID)
enum HSTV_CMD_ID : uint16_t {
    HSTV_CMD_NONE                 = 0x0000,

    // 核心业务命令 (0x0100 - 0x01FF)
    HSTV_CMD_LOGIN_REQ            = 0x0101, // 登录鉴权请求
    HSTV_CMD_LOGIN_ACK            = 0x0102, // 登录鉴权应答
    HSTV_CMD_CLOSE_LOADER_REQ     = 0x0103, // 关闭宿主端 Loader
    HSTV_CMD_CLOSE_LOADER_ACK     = 0x0104, // 关闭应答
    HSTV_CMD_MANUAL_CONNECT_REQ   = 0x0105, // 手动 TCP 连接同步
    HSTV_CMD_MANUAL_CONNECT_ACK   = 0x0106, // 手动连接应答
    // 服务发现与状态同步 (0x0200 - 0x02FF)
    HSTV_CMD_HEARTBEAT_REQ            = 0x0209, // 心跳保活
    HSTV_CMD_HEARTBEAT_ACK            = 0x020A, // 心跳响应
    HSTV_CMD_INJECT_GAME_REQ          = 0x020B, // 注入游戏请求
    HSTV_CMD_INJECT_GAME_ACK          = 0x020C, // 注入游戏应答
    HSTV_CMD_LEECHAGENT_PING_REQ      = 0x020D, // LeechAgent 探活请求
    HSTV_CMD_LEECHAGENT_PING_ACK      = 0x020E, // LeechAgent 探活应答
    HSTV_CMD_LEECHAGENT_CLOSE_REQ     = 0x0211, // 关闭 LeechAgent 请求
    HSTV_CMD_LEECHAGENT_CLOSE_ACK     = 0x0212, // 关闭 LeechAgent 应答
    HSTV_CMD_DECRYPT_DLL_CHECK_REQ    = 0x0213, // 校验解密 DLL MD5
    HSTV_CMD_DECRYPT_DLL_CHECK_ACK    = 0x0214, // 校验解密 DLL 应答

    // 载荷分发 (0x0300 - 0x03FF)
    HSTV_CMD_SHELLCODE_DATA_REQ   = 0x0301, // 独立 Shellcode 下发
    HSTV_CMD_SHELLCODE_DATA_ACK   = 0x0302, // Shellcode 接收确认

    // 驱动指令与数据流 (0x0400 - 0x04FF)
    HSTV_CMD_DRIVER_START_REQ     = 0x0401, // 驱动启动加载指令
    HSTV_CMD_DRIVER_START_ACK     = 0x0402, // 驱动启动就绪回执
    HSTV_CMD_DRIVER_DATA_REQ      = 0x0403, // 双机驱动数据下发请求
    HSTV_CMD_DRIVER_DATA_ACK      = 0x0404, // 双机驱动数据接收确认
};

// 1. 传统外层传输协议包头
struct PacketHeader
{
    uint32_t magic;      // PACKET_MAGIC ('HTLA')
    uint16_t version;    // 协议版本
    uint16_t flags;      // bit0=是否加密
    uint32_t bodySize;   // 数据体大小
    uint32_t crc32;      // CRC32（对加密后的 body）
};

// 2. 纯二进制协议基础头部 (所有 HSTV 二进制包均以 Magic + Cmd 起始)
struct HSTV_HEADER {
    uint32_t Magic;      // 0x56545348 ('HSTV')
    uint16_t Cmd;        // HSTV_CMD_ID
};

// 3. 通用基础命令包 (无复杂参数)
struct HSTV_BASIC_CMD {
    uint32_t Magic;      // 0x56545348 ('HSTV')
    uint16_t Cmd;        // CmdId
    uint16_t SubCmd;     // 子命令或保留
    uint32_t ExtraValue; // 附加数据值
};

// 4. 通用统一响应包 (Common ACK)
struct HSTV_COMMON_ACK {
    uint32_t Magic;      // 0x56545348 ('HSTV')
    uint16_t Cmd;        // 对应 ACK CmdId
    uint32_t Status;     // 0=成功, 非0=错误码
    char     Reason[64]; // 状态提示信息 (C字符串)
    uint32_t ExtraValue; // 附带参数值 (如端口或模式)
};

// 5. 登录鉴权请求包 (CMD_LOGIN_REQ)
struct HSTV_LOGIN_REQ {
    uint32_t Magic;          // 0x56545348 ('HSTV')
    uint16_t Cmd;            // HSTV_CMD_LOGIN_REQ (0x0101)
    char     CardKey[64];    // 卡密字符串
    char     Hwid[64];       // 客户端硬件指纹
    char     BrandVersion[32];  // 品牌/版本代号
    char     SelectedGame[32];  // 所选游戏标识 (如 deltaforce / naraka 等)
    char     ClientVersion[32]; // 客户端版本
    uint32_t ConnectMode;    // 预期通信模式 (1:DMA, 2:TCP, 3:UDP, 4:USB)
    uint16_t ConnectPort;    // 通信端口
    uint8_t  DriverMode;     // 驱动模式 (1=正常服务加载, 2=白驱动PTE内存映射)
    uint8_t  Reserved[9];    // 保留对齐
    char     ApiUrl[128];    // 业务 API 地址
    char     LoginUrl[128];  // 登录/鉴权 API 地址
    char     ReportUrl[128]; // 日志风控上报地址
};

// 6.2 解密 DLL 校验请求包 (CMD_DECRYPT_DLL_CHECK_REQ)
struct HSTV_DECRYPT_DLL_CHECK_REQ {
    uint32_t Magic;         // 0x56545348 ('HSTV')
    uint16_t Cmd;           // HSTV_CMD_DECRYPT_DLL_CHECK_REQ (0x0213)
    char     Md5[36];       // MD5 散列字符串
    uint8_t  Reserved[2];
};

// 7. 独立 Shellcode 载荷分发帧头 (CMD_SHELLCODE_DATA_REQ)
struct HSTV_CMD_SHELLCODE_REQ {
    uint32_t Magic;         // 0x56545348 ('HSTV')
    uint16_t Cmd;           // HSTV_CMD_SHELLCODE_DATA_REQ (0x0301)
    uint32_t ShellcodeType; // 1=GameShellcode, 2=LeechShellcode
    uint32_t CodeSize;      // Shellcode 字节数
    uint32_t ExtraSize;     // 附加数据字节数
    uint32_t Crc32;         // 载荷 CRC32
};

// 8. 结构化二进制指令帧：双机驱动数据下发请求包 (控制端 B -> 宿主端 host_loader，步骤 1)
struct HSTV_DRIVER_DATA_REQ {
    uint32_t Magic;             // 0x56545348 ('HSTV')
    uint16_t Cmd;               // 0x0403 (HSTV_CMD_DRIVER_DATA_REQ)
    uint8_t  ConnectMode;       // 2=WSK_TCP, 3=WSK_UDP, 4=USB_BULK
    uint8_t  DriverMode;        // 1=正常服务加载, 2=白驱动PTE内存映射
    uint32_t LeechCoreSize;     // Leech 核心驱动大小
    uint32_t WhiteDriverSize;   // 白驱动大小 (若 DriverMode==1 则为 0)
    uint32_t PayloadCRC32;      // 聚合负载流的 CRC32 强校验
};

// 8.1 结构化二进制指令帧：双机服务加载启动请求包 (控制端 B -> 宿主端 host_loader，步骤 2)
struct HSTV_DRIVER_START_REQ {
    uint32_t Magic;             // 0x56545348 ('HSTV')
    uint16_t Cmd;               // 0x0401 (HSTV_CMD_DRIVER_START_REQ)
    uint8_t  ConnectMode;       // 2=WSK_TCP, 3=WSK_UDP, 4=USB_BULK
    uint8_t  DriverMode;        // 1=正常服务加载, 2=白驱动PTE内存映射
    uint8_t  SessionToken[16];  // 云端下发的随机鉴权熵
    char     ApiUrl[128];       // 业务 API 地址
    char     LoginUrl[128];     // 登录/鉴权 API 地址
    char     ReportUrl[128];    // 日志风控上报地址
    char     CardKey[64];       // 卡密字符串
};

// 9. 结构化二进制指令帧：驱动就绪回执包 (宿主端 host_loader -> 控制端 B)
struct HSTV_CMD_DRIVER_INIT_ACK {
    uint32_t Magic;             // 0x56545348 ('HSTV')
    uint16_t Cmd;               // 0x0402 (HSTV_CMD_DRIVER_START_ACK)
    uint32_t StatusCode;        // NTSTATUS (0x00000000 = SUCCESS)
    uint16_t BoundDataPort;     // 驱动 WSK 实际监听端口
    uint16_t ConnectMode;       // 实际生效模式
    uint32_t WipedInitBytes;    // 驱动已物理擦除的 INIT 段字节数
    uint8_t  Reserved[16];
};

// 10. 驱动 IOCTL 控制码与启动验签结构
#ifndef IOCTL_MK_START_TRANSPORT
#define IOCTL_MK_START_TRANSPORT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#define DRV_BOOT_CONFIG_MAGIC 0x57534B43U // 'WSKC'

// 启动特性开关位掩码 (DRV_BOOT_CONFIG.Flags)
#define DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP 0x00000001 // 允许驱动异步粉碎删除宿主 Loader 进程与文件
#define DRV_BOOT_FLAG_DELETE_LOADER              DRV_BOOT_FLAG_ENABLE_HOST_LOADER_CLEANUP

struct DRV_BOOT_CONFIG {
    uint32_t Magic;            // DRV_BOOT_CONFIG_MAGIC ('WSKC')
    uint32_t TransportMode;    // 2 = WSK_TCP, 3 = WSK_UDP, 4 = USB
    uint16_t Port;             // 通信端口
    uint16_t Reserved;
    uint32_t AuthToken;        // 握手认证 Token
    uint32_t Flags;            // 特性开关
    uint8_t  SessionToken[16]; // 云端下发的随机鉴权熵
};

struct DRV_BOOT_CONFIG_EX {
    DRV_BOOT_CONFIG Base;
    wchar_t HostLoaderPath[260]; // 宿主加载器自身绝对路径
    char    ApiUrl[128];         // 业务 API 地址
    char    LoginUrl[128];       // 鉴权 API 地址
    char    ReportUrl[128];      // 上报 API 地址
    char    BrandVersion[32];    // 品牌版本
    char    SelectedGame[32];    // 所选游戏标识
    char    ClientVersion[32];   // 客户端版本
    char    CardKey[64];         // 卡密字符串
};




struct DRV_BOOT_RESPONSE {
    uint32_t Status;           // NTSTATUS (0 = SUCCESS)
    uint16_t BoundPort;        // 实际生效端口
    uint16_t TransportMode;    // 实际生效模式
    uint64_t DriverSignature;  // 驱动基于 Token 与内核私钥生成的 SipHash24 指纹
};
#pragma pack(pop)

#pragma pack(push, 1)
struct DRV_USER_PAYLOAD_ANCHOR
{
    uint64_t Tag0;       // 动态哈希 Tag0 (由动态 Token 派生)
    uint64_t Tag1;       // 动态哈希 Tag1 (~Tag0 ^ 0xA5A5A5A55A5A5A5AULL)
    uint32_t Nonce;      // 随机 Nonce 动态盐
    uint32_t CipherLen;  // 密文长度 (sizeof(DRV_BOOT_CONFIG_EX))
    uint32_t Checksum;   // 明文 Adler32 校验和
    uint32_t Reserved;   // 对齐填充
    uint8_t  CipherData[sizeof(DRV_BOOT_CONFIG_EX)]; // RC4 密文载荷
};
#pragma pack(pop)

bool tcp_server_create();
bool discvoer_service();