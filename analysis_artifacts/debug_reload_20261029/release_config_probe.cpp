#include "../../vt/common/vt_config.h"
#if VT_DEBUG_RELOAD_MODE
#error release profile unexpectedly debug
#endif
#if !VT_PAYLOAD_IMAGE_HIDE_ENABLED || !VT_MACHENIKE_TEXT_DUAL_VIEW_ENABLED
#error production hidden defaults missing
#endif
#if VT_FULL_UNLOAD_PRE_UNHIDE_ENABLED
#error release pre-unhide unexpectedly enabled
#endif
int main() { return 0; }
