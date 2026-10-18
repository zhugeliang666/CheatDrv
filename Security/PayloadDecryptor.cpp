#include "Common.h"
#include "DrvSecurity.h"
#include "Utils.h"
#include <ntimage.h>

NTSTATUS DrvSecurity::ScanAndDecryptUserPayload(IN ULONG devToken, OUT PDRV_BOOT_CONFIG_EX outConfig)
{
    if (!outConfig)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: outConfig is NULL");
        return STATUS_INVALID_PARAMETER;
    }

    // 1. 动态 Tag0/Tag1: 完全由当前调用传入的 devToken 实时派生 (无静态常量特征)
    UINT64 expectedTag0 = Utils::SipHash24(g_SipHashKey, (const UCHAR *)&devToken, sizeof(devToken));
    UINT64 expectedTag1 = ~expectedTag0 ^ 0xA5A5A5A55A5A5A5AULL;

    PEPROCESS pProcess = (g_pGlobalUserVar && g_pGlobalUserVar->Func.IoGetCurrentProcess)
                             ? g_pGlobalUserVar->Func.IoGetCurrentProcess()
                             : NULL;
    if (!pProcess)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: IoGetCurrentProcess returned NULL");
        return STATUS_INVALID_PARAMETER;
    }

    PVOID baseAddress = (g_pGlobalUserVar && g_pGlobalUserVar->Func.PsGetProcessSectionBaseAddress)
                            ? g_pGlobalUserVar->Func.PsGetProcessSectionBaseAddress(pProcess)
                            : NULL;
    if (!baseAddress)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: BaseAddress is NULL");
        return STATUS_NOT_FOUND;
    }

    NTSTATUS status = STATUS_NOT_FOUND;
    BOOLEAN bFoundTag = FALSE;

    __try
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)baseAddress;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Invalid DOS signature 0x%04X (expected 0x%04X)",
                pDos->e_magic, IMAGE_DOS_SIGNATURE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)baseAddress + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Invalid NT signature 0x%08X (expected 0x%08X)",
                pNt->Signature, IMAGE_NT_SIGNATURE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        for (USHORT i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++)
        {
            // 匹配读写数据节区 (.data 等)
            if ((pSec->Characteristics & IMAGE_SCN_MEM_READ) && (pSec->Characteristics & IMAGE_SCN_MEM_WRITE))
            {
                PUCHAR secVA = (PUCHAR)baseAddress + pSec->VirtualAddress;
                ULONG secSize = pSec->Misc.VirtualSize;

                if (secSize >= sizeof(DRV_USER_PAYLOAD_ANCHOR))
                {
                    ULONG maxOffset = secSize - sizeof(DRV_USER_PAYLOAD_ANCHOR);
                    for (ULONG offset = 0; offset <= maxOffset; offset += sizeof(ULONG_PTR))
                    {
                        PDRV_USER_PAYLOAD_ANCHOR pAnchor = (PDRV_USER_PAYLOAD_ANCHOR)(secVA + offset);
                        if (pAnchor->Tag0 == expectedTag0 && pAnchor->Tag1 == expectedTag1)
                        {
                            bFoundTag = TRUE;
                            if (pAnchor->CipherLen != sizeof(DRV_BOOT_CONFIG_EX))
                            {
                                DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Tag matched but CipherLen mismatch "
                                    "(%u != %u)",
                                    pAnchor->CipherLen, (ULONG)sizeof(DRV_BOOT_CONFIG_EX));
                                continue;
                            }

                            // 派生解密密钥: g_SipHashKey (16B) + devToken (4B) + Nonce (4B)
                            UCHAR key[24];
                            memcpy(&key[0], g_SipHashKey, 16);
                            memcpy(&key[16], &devToken, 4);
                            memcpy(&key[20], &pAnchor->Nonce, 4);

                            DRV_BOOT_CONFIG_EX plainCfg;
                            memcpy(&plainCfg, pAnchor->CipherData, sizeof(DRV_BOOT_CONFIG_EX));
                            Utils::Rc4Decrypt((UCHAR *)&plainCfg, sizeof(DRV_BOOT_CONFIG_EX), key, sizeof(key));

                            // 校验 Adler32 与 Magic
                            ULONG calcSum = Utils::CalcAdler32((const UCHAR *)&plainCfg, sizeof(plainCfg));
                            if (plainCfg.Base.Magic == DRV_BOOT_CONFIG_MAGIC && calcSum == pAnchor->Checksum)
                            {
                                memcpy(outConfig, &plainCfg, sizeof(DRV_BOOT_CONFIG_EX));

                                // 阅后即焚: 内核特权清零用户态内存中的锚点标记与密文，杜绝取证残留
                                RtlSecureZeroMemory(pAnchor, sizeof(DRV_USER_PAYLOAD_ANCHOR));
                                status = STATUS_SUCCESS;
                                break;
                            }
                            else
                            {
                                DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Payload validation failed! "
                                    "Magic=0x%08X (exp 0x%08X), Checksum=0x%08X (exp 0x%08X)",
                                    plainCfg.Base.Magic, DRV_BOOT_CONFIG_MAGIC, calcSum, pAnchor->Checksum);
                            }
                        }
                    }
                }
                if (status == STATUS_SUCCESS)
                    break;
            }
        }
        if (status != STATUS_SUCCESS && !bFoundTag)
        {
            DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Target anchor tags not found in user memory "
                "(Token=0x%08X, expectedTag0=0x%016llX)",
                devToken, expectedTag0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: SEH exception 0x%08X while scanning user memory", status);
    }

    return status;
}
