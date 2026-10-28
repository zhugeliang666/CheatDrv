#include "../../vt/common/vt_config.h"
#if !VT_DEBUG_RELOAD_MODE
#error debug profile missing
#endif
#if !VT_BOOT_KEEP_CONTROL_DEVICE || VT_BOOT_DROP_CONTROL_DEVICE
#error control device profile mismatch
#endif
#if !VT_PAYLOAD_IMAGE_HIDE_ENABLED || !VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED || !VT_HIDE_PAYLOAD_ENABLED || !VT_HIDE_PAYLOAD_IMAGE || !VT_HIDE_PAYLOAD_ARENA || !VT_HIDE_PAYLOAD_DIRECT || !VT_HIDE_FULL_ARENA || !VT_HIDE_RESIDENT_POOLS_AFTER_HANDOFF
#error hidden feature profile mismatch
#endif
#if !VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED
#error debug full-unload unhide gate missing
#endif
int main() { return 0; }
