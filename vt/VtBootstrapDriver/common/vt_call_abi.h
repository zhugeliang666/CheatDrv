#pragma once

// Machenike CallUser/CallKernel 与 ResidentPayload 的固定宽度调用协议。
#define VT_CALL_API_MAGIC       0x5643414CUL // 'VCAL'
#define VT_CALL_API_VERSION     1U
#define VT_CALL_MAX_ARGS        12U
#define VT_CALL_SUBCMD_USER     0x7000U
#define VT_CALL_SUBCMD_KERNEL   0x7001U

enum vt_call_mode : unsigned int
{
    VT_CALL_MODE_USER = 0,
    VT_CALL_MODE_KERNEL = 1,
};

enum vt_call_status : unsigned int
{
    VT_CALL_STATUS_OK = 0,
    VT_CALL_STATUS_BAD_REQUEST = 1,
    VT_CALL_STATUS_EXECUTION_FAILED = 2,
};

#pragma pack(push, 8)
struct vt_call_request
{
    unsigned int magic;
    unsigned short version;
    unsigned short size;
    unsigned int mode;
    unsigned int arg_count;
    unsigned long long target;
    unsigned long long args[VT_CALL_MAX_ARGS];
};

struct vt_call_response
{
    unsigned int magic;
    unsigned short version;
    unsigned short size;
    unsigned int status;
    unsigned int mode;
    unsigned long long target;
    unsigned long long return_value;
};
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(vt_call_request) == 120, "Call request ABI drift");
static_assert(sizeof(vt_call_response) == 32, "Call response ABI drift");
#endif
