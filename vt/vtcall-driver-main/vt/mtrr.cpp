#include "mtrr.h"

#include <cstdint>

#include "arch.h"

namespace hv {
#pragma code_seg(".vm")
#define PAGE_SIZE 0x1024
#define PAGE_2M_SIZE 0x200000

	   void read_mtrr_data(vcpu_ept_data &ept)
	   {
	       auto mtrrs = &ept.mtrrs;
	       mtrrs->cap.flags = __readmsr(IA32_MTRR_CAPABILITIES);
	       mtrrs->def_type.flags = __readmsr(IA32_MTRR_DEF_TYPE);
	       mtrrs->mtrr_range_count = 0;


	       if (!mtrrs->def_type.mtrr_enable)
	       {
	           mtrrs->default_memory_type = MEMORY_TYPE_UNCACHEABLE;
	           return;
	       }

	       //setting default

	       mtrrs->default_memory_type = mtrrs->def_type.default_memory_type;


	       int32_t number_of_bits_in_mask = 0;
	       ia32_mtrr_physbase_register current_phys_base;
	       ia32_mtrr_physmask_register current_phys_mask;

	       if (mtrrs->cap.smrr_supported)
	       {
	           current_phys_base.flags = __readmsr(IA32_SMRR_PHYSBASE);
	           current_phys_mask.flags = __readmsr(IA32_SMRR_PHYSMASK);
	           if (current_phys_mask.valid && current_phys_base.type != mtrrs->default_memory_type)
	           {
	               auto descriptor = &mtrrs->mtrr_range[mtrrs->mtrr_range_count++];
	               descriptor->physical_base_address = current_phys_base.page_frame_number << 12;
	               descriptor->fixed_range = false;
	               unsigned long bits_in_mask = 0;
	               _BitScanForward64(&bits_in_mask, current_phys_mask.page_frame_number << 12);
	               descriptor->memory_type = current_phys_base.type;  
	               descriptor->physical_end_address = descriptor->physical_base_address + ((1ULL << bits_in_mask) - 1ULL);
	           }
	       }


	       if (mtrrs->cap.fixed_range_supported && mtrrs->def_type.fixed_range_mtrr_enable)
	       {

	           typedef union _IA32_MTRR_FIXED_RANGE_TYPE
	           {
	               
	               int64_t flags;
	               struct
	               {
	                   int8_t types[8];
	               };

	           } IA32_MTRR_FIXED_RANGE_TYPE;

	           const int32_t k64_base = 0x0;
	           const int32_t k64_size = 0x10000;

	           IA32_MTRR_FIXED_RANGE_TYPE k64_types = { (int64_t)__readmsr(IA32_MTRR_FIX64K_00000) };

	           for (int32_t i = 0; i < 8; i++)
	           {
	               auto descriptor = &mtrrs->mtrr_range[mtrrs->mtrr_range_count++];
	               descriptor->physical_base_address = k64_base + (k64_size * i);
	               descriptor->physical_end_address = k64_base + (k64_size * i) + (k64_size - 1);
	               descriptor->fixed_range = true;
	               descriptor->memory_type = k64_types.types[i];
	           }

	           const int64_t k16_base = 0x80000;
	           const int64_t k16_size = 0x4000;
	           for (int32_t i = 0; i < 2; i++)
	           {
	               IA32_MTRR_FIXED_RANGE_TYPE k16_types = { (int64_t)__readmsr(IA32_MTRR_FIX16K_80000 + i) };

	   			for (int32_t j = 0;j < 8;j++)
	   			{
	                  
	                   auto descriptor = &mtrrs->mtrr_range[mtrrs->mtrr_range_count++];
	                   descriptor->physical_base_address = (k16_base + (i * k16_size * 8)) + (k16_size * j);
	                   descriptor->physical_end_address = (k16_base + (i * k16_size * 8)) + (k16_size * j) + (k16_size - 1);
	                   descriptor->fixed_range = true;
	                   descriptor->memory_type = k16_types.types[j];
	   			}
	           }

	           const int64_t k4_base = 0xc0000;
	           const int64_t k4_size = 0x1000;
	           for (int32_t i = 0; i < 8; i++)
	           {
	               IA32_MTRR_FIXED_RANGE_TYPE k4_types = { (int64_t)__readmsr(IA32_MTRR_FIX4K_C0000 + i) };

	               for (int32_t j = 0; j < 8; j++)
	               {
	                  
	                   auto descriptor = &mtrrs->mtrr_range[mtrrs->mtrr_range_count++];
	                   descriptor->physical_base_address = k4_base + (k4_size * j ) + (k4_size * i * 8);
	                   descriptor->physical_end_address = k4_base + (k4_size * j ) + +(k4_size * i * 8) + (k4_size - 1);
	                   descriptor->fixed_range = true;
	                   descriptor->memory_type = k4_types.types[j];
	               }
	           }

	       }


	       for (uint32_t i = 0; i < mtrrs->cap.variable_range_count; ++i)
	       {


	           current_phys_base.flags = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
	           current_phys_mask.flags = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));


	           if (current_phys_mask.valid && current_phys_base.type != mtrrs->default_memory_type)
	           {
	               auto descriptor = &mtrrs->mtrr_range[mtrrs->mtrr_range_count++];
	               descriptor->physical_base_address = current_phys_base.page_frame_number << 12;
	               unsigned long bits_in_mask = 0;
	               _BitScanForward64(&bits_in_mask, current_phys_mask.page_frame_number << 12);
	               descriptor->physical_end_address = descriptor->physical_base_address + +((1ULL << bits_in_mask) - 1ULL);
	               descriptor->fixed_range = false;
	               descriptor->memory_type = current_phys_base.type;
	           }

	       }
	   }

	   // calculate the MTRR memory type for a single page
	   uint8_t calc_mtrr_mem_type(mtrr_data const& mtrrs, uint64_t const pfn, bool is_large_paga)
	   {
	       uint64_t start = is_large_paga ? pfn * PAGE_2M_SIZE : pfn * PAGE_SIZE;
	       uint64_t end = is_large_paga ? start + (PAGE_2M_SIZE - 1) : (start + PAGE_SIZE - 1);


	       uint64_t curr_mem_type = mtrrs.default_memory_type;

	       for (int32_t i = 0; i < mtrrs.mtrr_range_count; i++)
	       {
	           auto memory_range = &mtrrs.mtrr_range[i];

	           if (start >= memory_range->physical_base_address && end <= memory_range->physical_end_address)
	           {

	               curr_mem_type = mtrrs.mtrr_range[i].memory_type;

	               if (memory_range->fixed_range) break;

	               if (memory_range->memory_type == MEMORY_TYPE_UNCACHEABLE)
	                   break;

	              

	           }
	       }

	       return curr_mem_type;
	   }



} // namespace hv

