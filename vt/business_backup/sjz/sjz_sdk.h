#pragma once
//
// sjz/sjz_sdk.h - legacy umbrella header.
//
// During R1 the SDK was split into reader / world / decrypt / internal.
// This header now re-exports them so callers that still `#include
// "sjz_sdk.h"` keep compiling. R3 will remove this file entirely and
// migrate the callers to the specific sub-module headers.
//
#include "internal.h"
#include "reader.h"
#include "world.h"
#include "decrypt.h"
