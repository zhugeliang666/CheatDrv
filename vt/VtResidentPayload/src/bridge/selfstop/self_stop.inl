// Split from payload_bridge.inl: selfstop/self_stop.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

static payload_u64 PayloadBridgeVmreadOrZero(payload_u64 field)
{
    payload_u64 value = 0;
    PayloadVmread(field, &value);
    return value;
}

#pragma pack(push, 1)
struct payload_bridge_descriptor_register
{
    unsigned short limit;
    payload_u64 base;
};
#pragma pack(pop)

static bool PayloadBridgePrepareSelfStopGuestState()
{
    payload_u64 guest = 0;
    payload_u64 mask = 0;
    payload_u64 shadow = 0;

    if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR0, &guest) &&
        PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_GUEST_HOST_MASK, &mask) &&
        PayloadVmread(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW, &shadow))
    {
        PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR0_READ_SHADOW,
                       (shadow & mask) | (guest & ~mask));
    }

    if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR4, &guest) &&
        PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_GUEST_HOST_MASK, &mask) &&
        PayloadVmread(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW, &shadow))
    {
        PayloadVmwrite(PAYLOAD_VMCS_CTRL_CR4_READ_SHADOW,
                       (shadow & mask) | (guest & ~mask));
    }

    payload_u64 value = 0;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_DR7, &value))
        __writedr(7, value);

    if (PayloadVmread(PAYLOAD_VMCS_GUEST_SYSENTER_CS, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_SYSENTER_CS, value);
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_SYSENTER_ESP, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_SYSENTER_ESP, value);
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_SYSENTER_EIP, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_SYSENTER_EIP, value);
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_PAT, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_PAT, value);
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_DEBUGCTL, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_DEBUGCTL, value);

    payload_u64 guest_cr3 = 0;
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_CR3, &guest_cr3) && guest_cr3)
        __writecr3(guest_cr3);

    payload_bridge_descriptor_register gdtr = {};
    payload_bridge_descriptor_register idtr = {};
    gdtr.base = PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_GDTR_BASE);
    gdtr.limit = (unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_GDTR_LIMIT);
    idtr.base = PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_IDTR_BASE);
    idtr.limit = (unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_IDTR_LIMIT);

    if (gdtr.base)
        PayloadLoadGdtr(&gdtr);
    if (idtr.base)
        PayloadLoadIdtr(&idtr);

    unsigned short tr = (unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_TR_SELECTOR);
    if (gdtr.base && tr)
    {
        payload_u64 index = (tr >> 3) & 0x1FFFull;
        unsigned char* type_byte = (unsigned char*)(gdtr.base + index * 8ull + 5ull);
        *type_byte = (unsigned char)((*type_byte & 0xF0u) | 0x09u); // available TSS
        PayloadWriteTr(tr);
    }

    PayloadWriteDs((unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_DS_SELECTOR));
    PayloadWriteEs((unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_ES_SELECTOR));
    PayloadWriteFs((unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_FS_SELECTOR));
    PayloadWriteGs((unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_GS_SELECTOR));
    PayloadWriteLdtr((unsigned short)PayloadBridgeVmreadOrZero(PAYLOAD_VMCS_GUEST_LDTR_SELECTOR));

    if (PayloadVmread(PAYLOAD_VMCS_GUEST_FS_BASE, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_FS_BASE, value);
    if (PayloadVmread(PAYLOAD_VMCS_GUEST_GS_BASE, &value))
        __writemsr((unsigned long)PAYLOAD_IA32_GS_BASE, value);

    return true;
}

static void PayloadBridgeMarkSelfUnloadAck()
{
    if (!g_hv_diag_cache_ready ||
        !PayloadIsKernelPointer(g_cached_hv_diag.ghv) ||
        !g_cached_hv_diag.ghv_off_stop_ack_bitmap)
    {
        return;
    }

    payload_u64 index = PayloadCurrentVcpuIndex();
    if (index >= 64)
        return;

    payload_u64 field = g_cached_hv_diag.ghv + g_cached_hv_diag.ghv_off_stop_ack_bitmap;
    if (!PayloadIsKernelPointer(field))
        return;

    _InterlockedOr64((volatile LONG64*)field, (LONG64)(1ull << index));
}

