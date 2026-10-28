#include "../../vt/common/vt_config.h"
#if !VT_DEBUG_RELOAD_MODE
#error debug mode override missing
#endif
#if VT_PAYLOAD_IMAGE_HIDE_ENABLED || VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED || VT_HIDE_PAYLOAD_ENABLED || VT_BOOT_DROP_CONTROL_DEVICE
#error debug mode did not disable hide/reload controls
#endif
int main() { return 0; }
