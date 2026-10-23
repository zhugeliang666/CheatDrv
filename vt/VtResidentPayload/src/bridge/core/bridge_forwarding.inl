// Split from payload_bridge.inl: core/bridge_forwarding.inl.
// Included by payload_bridge.inl; keep this in the same translation unit.

enum payload_bridge_forward_kind : payload_u64
{
    PAYLOAD_BRIDGE_FORWARD_GENERIC = 0,
    PAYLOAD_BRIDGE_FORWARD_BAD_KEY = 1,
    PAYLOAD_BRIDGE_FORWARD_UNKNOWN_CODE = 2,
    PAYLOAD_BRIDGE_FORWARD_NON_VMCALL = 3,
};

static void PayloadRecordRipHistogram(
    payload_u64 rip,
    volatile payload_u64* addrs,
    volatile payload_u64* counts,
    volatile LONG64* next_slot)
{
    if (!rip || !addrs || !counts || !next_slot)
        return;

    for (payload_u64 i = 0; i < PAYLOAD_RIP_HIST_SLOTS; ++i)
    {
        if (addrs[i] == rip)
        {
            _InterlockedIncrement64((volatile LONG64*)&counts[i]);
            return;
        }
    }

    for (payload_u64 i = 0; i < PAYLOAD_RIP_HIST_SLOTS; ++i)
    {
        if (addrs[i] == 0)
        {
            if (_InterlockedCompareExchange64((volatile LONG64*)&addrs[i], (LONG64)rip, 0) == 0)
            {
                _InterlockedIncrement64((volatile LONG64*)&counts[i]);
                return;
            }
        }
    }

    payload_u64 slot = (payload_u64)(_InterlockedIncrement64(next_slot) - 1) & (PAYLOAD_RIP_HIST_SLOTS - 1);
    addrs[slot] = rip;
    counts[slot] = 1;
}

