#pragma once
#include <fltKernel.h>

namespace dwm {

	void bootstrap_tramp_pool(ULONG64 image_base, ULONG64 image_size, bool is_kernel);

}
