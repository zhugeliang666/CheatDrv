#pragma once

#include <ia32.hpp>

#include "ept.h"

namespace hv {


	extern struct mtrr_data;

	extern struct vcpu_ept_data;


// //读取 MTRR data into a single 结构体
void read_mtrr_data(vcpu_ept_data& ept);


// //calculate the MTRR memory type for the given 物理内存 range
uint8_t calc_mtrr_mem_type(mtrr_data const& mtrrs, uint64_t const pfn, bool is_large_paga);



} // namespace hv

