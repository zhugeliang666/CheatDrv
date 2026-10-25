#pragma once

#include "vmx.h"
#include "mm.h"

#include <ntddk.h>

namespace hv {

// 获取 the KPCR of the 当前 guest (this 指针 should stay constant per-vcpu)
PKPCR current_guest_kpcr();

// 获取 the ETHREAD of the 当前 guest
PETHREAD current_guest_ethread();

// 获取 the EPROCESS of the 当前 guest
PEPROCESS current_guest_eprocess();

// 获取 the PID of the 当前 guest
uint64_t current_guest_pid();

// 获取 the kernel CR3 of the 当前 guest
cr3 current_guest_cr3();

// 获取 the image file name (up to 15 chars) of the 当前 guest process
bool current_guest_image_file_name(char (&name)[16]);

} // namespace hv

