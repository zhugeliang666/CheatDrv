#pragma once

#include "FrameWork.h"

#pragma warning(disable : 4200)
#pragma warning(disable : 4201)
#pragma warning(disable : 4996)

#ifndef BOOL
typedef int BOOL;
typedef int *PBOOL;
#endif

#define LEECHRPC_MSGMAGIC 0xd05a2667
#define LEECHRPC_FLAG_NOCOMPRESS 0x0010
#define LEECHRPC_FLAG_FNEXIST_ReadScatterMEM 0x0100
#define LEECHRPC_FLAG_FNEXIST_WriteScatterMEM 0x0200
#define LEECHRPC_FLAG_FNEXIST_Close 0x0800
#define LEECHRPC_FLAG_FNEXIST_GetOption 0x1000
#define LEECHRPC_FLAG_FNEXIST_SetOption 0x2000
#define LEECHRPC_FLAG_FNEXIST_Command 0x4000

#ifndef COMPRESSION_FORMAT_XPRESS
#define COMPRESSION_FORMAT_NONE (0x0000)
#define COMPRESSION_FORMAT_DEFAULT (0x0001)
#define COMPRESSION_FORMAT_LZNT1 (0x0002)
#define COMPRESSION_FORMAT_XPRESS (0x0003)
#define COMPRESSION_FORMAT_XPRESS_HUFF (0x0004)
#define COMPRESSION_ENGINE_STANDARD (0x0000)
#define COMPRESSION_ENGINE_MAXIMUM (0x0100)
#endif

#define LC_CONFIG_VERSION 0xc0fd0002
#define LC_CONFIG_ERRORINFO_VERSION 0xc0fe0002
#define MEM_SCATTER_VERSION 0xc0fe0002
#define MEM_SCATTER_STACK_SIZE 12

#define LC_CMD_STATISTICS_GET 0x4000010000000000ULL
#define LC_CMD_MEMMAP_GET 0x4000020000000000ULL
#define LC_CMD_MEMMAP_SET 0x4000030000000000ULL
#define LC_CMD_MEMMAP_GET_STRUCT 0x4000040000000000ULL
#define LC_CMD_MEMMAP_SET_STRUCT 0x4000050000000000ULL

#define LC_OPT_CORE_PRINTF_ENABLE 0x4000000100000000ULL
#define LC_OPT_CORE_VERBOSE 0x4000000200000000ULL
#define LC_OPT_CORE_VERBOSE_EXTRA 0x4000000300000000ULL
#define LC_OPT_CORE_VERBOSE_EXTRA_TLP 0x4000000400000000ULL
#define LC_OPT_CORE_VERSION_MAJOR 0x4000000500000000ULL
#define LC_OPT_CORE_VERSION_MINOR 0x4000000600000000ULL
#define LC_OPT_CORE_VERSION_REVISION 0x4000000700000000ULL
#define LC_OPT_CORE_ADDR_MAX 0x1000000800000000ULL
#define LC_OPT_CORE_VOLATILE 0x1000000b00000000ULL
#define LC_OPT_CORE_READONLY 0x1000000c00000000ULL

#define LC_OPT_MEMORYINFO_VALID 0x0200000100000000ULL
#define LC_OPT_MEMORYINFO_FLAG_32BIT 0x0200000300000000ULL
#define LC_OPT_MEMORYINFO_FLAG_PAE 0x0200000400000000ULL
#define LC_OPT_MEMORYINFO_OS_VERSION_MINOR 0x0200000500000000ULL
#define LC_OPT_MEMORYINFO_OS_VERSION_MAJOR 0x0200000600000000ULL
#define LC_OPT_MEMORYINFO_OS_DTB 0x0200000700000000ULL
#define LC_OPT_MEMORYINFO_OS_PFN 0x0200000800000000ULL
#define LC_OPT_MEMORYINFO_OS_PsLoadedModuleList 0x0200000900000000ULL
#define LC_OPT_MEMORYINFO_OS_PsActiveProcessHead 0x0200000a00000000ULL
#define LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP 0x0200000b00000000ULL
#define LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS 0x0200000c00000000ULL
#define LC_OPT_MEMORYINFO_OS_SYSTEMTIME 0x0200000d00000000ULL
#define LC_OPT_MEMORYINFO_OS_UPTIME 0x0200000e00000000ULL
#define LC_OPT_MEMORYINFO_OS_KERNELBASE 0x0200000f00000000ULL
#define LC_OPT_MEMORYINFO_OS_KERNELHINT 0x0200001000000000ULL
#define LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock 0x0200001100000000ULL
#define LC_OPT_MEMORYINFO_ARCH 0x0200001200000000ULL

#define LC_CMD_AGENT_EXIT_PROCESS 0x8000000200000000ULL
#define LC_CMD_AGENT_GET_MSR 0x8000000a00000000ULL
#define LC_CMD_AGENT_EXEC_BYTECODE 0x8000000b00000000ULL
#define LC_CMD_AGENT_UNLOAD_DRIVER 0x8000000c00000000ULL
#define LC_CMD_BENCHMARK_READ_1S 0x8000000d00000000ULL

#pragma pack(push, 8)
typedef struct _LC_CMD_BENCHMARK_REQ
{
    ULONG64 qwPhysicalAddress; // 可选：指定压测读取的目标物理地址 (为0默认0x1000)
    ULONG cbRead;              // 可选：单次读取长度 (为0默认PAGE_SIZE)
    ULONG Reserved;            // 8字节对齐填充
} LC_CMD_BENCHMARK_REQ, *PLC_CMD_BENCHMARK_REQ;

typedef struct _LC_CMD_BENCHMARK_RSP
{
    ULONG64 TotalOperations; // 1秒实际读取总次数 (QPS)
    ULONG64 TotalBytes;      // 1秒读取总字节数
    ULONG64 FastPathHits;    // 快路径无锁直读命中次数
    ULONG64 Elapsed100ns;    // 实际压测耗时 (100ns 单位)
    ULONG64 Qps;             // 换算每秒读取次数
    ULONG64 BandwidthMBs;    // 吞吐带宽整数部分 (MB/s)
    ULONG64 BandwidthDecMBs; // 吞吐带宽小数部分 (两位有效数字)
    ULONG64 HitRatePercent;  // 快路径命中率百分比 (0~100)
} LC_CMD_BENCHMARK_RSP, *PLC_CMD_BENCHMARK_RSP;
#pragma pack(pop)

typedef enum _VM_OPCODE
{
    VM_OP_LOAD_IMM = 0x01,  // R[dst] = imm32
    VM_OP_READ_VA64 = 0x02, // R[dst] = Read64(R[src] + imm32)
    VM_OP_READ_VA32 = 0x03, // R[dst] = Read32(R[src] + imm32)
    VM_OP_ADD = 0x10,       // R[dst] = R[dst] + R[src]
    VM_OP_ADD_IMM = 0x11,   // R[dst] = R[dst] + imm32
    VM_OP_SUB = 0x12,       // R[dst] = R[dst] - R[src]
    VM_OP_XOR = 0x13,       // R[dst] = R[dst] ^ R[src]
    VM_OP_ROR32 = 0x14,     // R[dst] = ROR32(R[dst], R[src] & 0x1F)
    VM_OP_AND_IMM = 0x15,   // R[dst] = R[dst] & imm32
    VM_OP_SHL_IMM = 0x16,   // R[dst] = R[dst] << imm32
    VM_OP_SHR_IMM = 0x17,   // R[dst] = R[dst] >> imm32
    VM_OP_OR = 0x18,        // R[dst] = R[dst] | R[src]
    VM_OP_JMP = 0x20,       // unconditional goto imm32
    VM_OP_JMP_EQ = 0x21,    // if (R[dst] == R[src]) goto imm32
    VM_OP_JMP_NE = 0x22,    // if (R[dst] != R[src]) goto imm32
    VM_OP_JMP_LT = 0x23,    // if (R[dst] < R[src]) goto imm32
    VM_OP_JMP_LE = 0x24,    // if (R[dst] <= R[src]) goto imm32
    VM_OP_JMP_GT = 0x25,    // if (R[dst] > R[src]) goto imm32
    VM_OP_JMP_GE = 0x26,    // if (R[dst] >= R[src]) goto imm32
    VM_OP_RET = 0xFF        // return R[dst]
} VM_OPCODE;

#pragma pack(push, 1)
typedef struct _VM_INSTRUCTION
{
    UCHAR op;     // VM_OPCODE
    UCHAR regDst; // Destination register (R0-R7)
    UCHAR regSrc; // Source register (R0-R7)
    UCHAR reserved;
    ULONG imm32; // Immediate value or branch target / offset
} VM_INSTRUCTION, *PVM_INSTRUCTION;

typedef struct _LC_CMD_AGENT_BYTECODE_REQ
{
    ULONG64 qwCr3;
    ULONG cInstructions;
    VM_INSTRUCTION Instructions[];
} LC_CMD_AGENT_BYTECODE_REQ, *PLC_CMD_AGENT_BYTECODE_REQ;

typedef struct _LC_CMD_AGENT_BYTECODE_RSP
{
    LONG fSuccess;
    ULONG dwError;
    ULONG64 qwResult;
} LC_CMD_AGENT_BYTECODE_RSP, *PLC_CMD_AGENT_BYTECODE_RSP;

typedef struct _LC_CMD_AGENT_MSR_REQ
{
    ULONG64 qwMsr;
    ULONG dwTag;
} LC_CMD_AGENT_MSR_REQ, *PLC_CMD_AGENT_MSR_REQ;

typedef struct _LC_CMD_AGENT_MSR_RSP
{
    LONG fSuccess;
    ULONG dwError;
    ULONG64 qwValue;
    ULONG dwTag;
} LC_CMD_AGENT_MSR_RSP, *PLC_CMD_AGENT_MSR_RSP;
#pragma pack(pop)

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

typedef enum _LEECHRPC_MSGTYPE
{
    LEECHRPC_MSGTYPE_NA = 0,
    LEECHRPC_MSGTYPE_PING_REQ = 1,
    LEECHRPC_MSGTYPE_PING_RSP = 2,
    LEECHRPC_MSGTYPE_OPEN_REQ = 3,
    LEECHRPC_MSGTYPE_OPEN_RSP = 4,
    LEECHRPC_MSGTYPE_CLOSE_REQ = 5,
    LEECHRPC_MSGTYPE_CLOSE_RSP = 6,
    LEECHRPC_MSGTYPE_READSCATTER_REQ = 7,
    LEECHRPC_MSGTYPE_READSCATTER_RSP = 8,
    LEECHRPC_MSGTYPE_WRITESCATTER_REQ = 9,
    LEECHRPC_MSGTYPE_WRITESCATTER_RSP = 10,
    LEECHRPC_MSGTYPE_GETOPTION_REQ = 11,
    LEECHRPC_MSGTYPE_GETOPTION_RSP = 12,
    LEECHRPC_MSGTYPE_SETOPTION_REQ = 13,
    LEECHRPC_MSGTYPE_SETOPTION_RSP = 14,
    LEECHRPC_MSGTYPE_COMMAND_REQ = 15,
    LEECHRPC_MSGTYPE_COMMAND_RSP = 16,
    LEECHRPC_MSGTYPE_KEEPALIVE_REQ = 17,
    LEECHRPC_MSGTYPE_KEEPALIVE_RSP = 18,
    LEECHRPC_MSGTYPE_MAX = 18,
} LEECHRPC_MSGTYPE;

typedef struct _LEECHRPC_MSG_HDR
{
    ULONG dwMagic;
    ULONG cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    LONG fMsgResult;
    ULONG dwRpcClientID;
    ULONG flags;
} LEECHRPC_MSG_HDR, *PLEECHRPC_MSG_HDR;

#pragma pack(push, 8)
typedef struct _LEECHRPC_MSG_HEARTBEAT
{
    LEECHRPC_MSG_HDR Hdr;
    ULONG64 qwChallenge; // 本端发出的 64 位 Nonce 挑战
    ULONG64 qwResponse;  // 针对对端上一轮挑战 + SessionKey 计算的响应
} LEECHRPC_MSG_HEARTBEAT, *PLEECHRPC_MSG_HEARTBEAT;
#pragma pack(pop)

typedef struct _LC_CONFIG
{
    ULONG dwVersion;
    ULONG dwPrintfVerbosity;
    CHAR szDevice[MAX_PATH];
    CHAR szRemote[MAX_PATH];
    PVOID pfn_printf_opt;
    ULONG64 paMax;
    LONG fVolatile;
    LONG fWritable;
    LONG fRemote;
    LONG fRemoteDisableCompress;
    CHAR szDeviceName[MAX_PATH];
} LC_CONFIG, *PLC_CONFIG;

typedef struct _LC_CONFIG_ERRORINFO
{
    ULONG dwVersion;
    ULONG cbStruct;
    ULONG _FutureUse[16];
    LONG fUserInputRequest;
    ULONG cwszUserText;
    WCHAR wszUserText[];
} LC_CONFIG_ERRORINFO, *PLC_CONFIG_ERRORINFO, **PPLC_CONFIG_ERRORINFO;

typedef struct _LC_STATISTICS
{
    ULONG dwVersion;
    ULONG _Reserved;
    ULONG64 qwFreq;
    ULONG64 cAction[32];
} LC_STATISTICS, *PLC_STATISTICS;

typedef struct _LEECHRPC_MSG_OPEN
{
    ULONG dwMagic;
    ULONG cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    LONG fMsgResult;
    ULONG dwRpcClientID;
    ULONG flags;

    LONG fValidOpen;
    LC_CONFIG cfg;
    LC_CONFIG_ERRORINFO errorinfo;
} LEECHRPC_MSG_OPEN, *PLEECHRPC_MSG_OPEN;

typedef struct _LEECHRPC_MSG_CHAIN
{
    ULONG dwMagic;
    ULONG cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    LONG fMsgResult;
    ULONG dwRpcClientID;
    ULONG flags;

    ULONG dwPid;
    ULONG cOffsets;
    ULONG64 qwCr3;
    ULONG64 qwBaseAddr;
    ULONG64 Offsets[];
} LEECHRPC_MSG_CHAIN, *PLEECHRPC_MSG_CHAIN;

typedef struct _LEECHRPC_MSG_BIN
{
    ULONG dwMagic;
    ULONG cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    LONG fMsgResult;
    ULONG dwRpcClientID;
    ULONG flags;

    ULONG64 qwData[2];
    ULONG cbDecompress;
    ULONG cb;
    UCHAR pb[];
} LEECHRPC_MSG_BIN, *PLEECHRPC_MSG_BIN;

typedef struct _LEECHRPC_MSG_DATA
{
    ULONG dwMagic;
    ULONG cbMsg;
    LEECHRPC_MSGTYPE tpMsg;
    LONG fMsgResult;
    ULONG dwRpcClientID;
    ULONG flags;

    ULONG64 qwData[2];
} LEECHRPC_MSG_DATA, *PLEECHRPC_MSG_DATA;

typedef struct _MEM_SCATTER
{
    ULONG version;
    LONG f;
    ULONG64 qwA;
    union
    {
        PUCHAR pb;
        ULONG64 _Filler;
    };
    ULONG cb;
    ULONG iStack;
    ULONG64 vStack[MEM_SCATTER_STACK_SIZE];
} MEM_SCATTER, *PMEM_SCATTER;

typedef struct _LC_MEMMAP_ENTRY
{
    ULONG64 pa;
    ULONG64 cb;
    ULONG64 paRemap;
} LC_MEMMAP_ENTRY, *PLC_MEMMAP_ENTRY;
