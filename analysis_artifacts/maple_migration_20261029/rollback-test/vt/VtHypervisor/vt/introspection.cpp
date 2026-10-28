#include "../base.h"
#include "introspection.h"
#include "mm.h"
#include "hv.h"

namespace hv {

// 获取 the KPCR of the 当前 guest (this 指针 should stay constant per-vcpu)
PKPCR current_guest_kpcr() {
  // GS base holds the KPCR when in ring-0
  if (current_guest_cpl() == 0)
    return reinterpret_cast<PKPCR>(vmx_vmread(VMCS_GUEST_GS_BASE));

  // when in ring-3, the GS_SWAP contains the KPCR
  return reinterpret_cast<PKPCR>(__readmsr(IA32_KERNEL_GS_BASE));
}

// 获取 the ETHREAD of the 当前 guest
PETHREAD current_guest_ethread() {
  // KPCR
  auto const kpcr = current_guest_kpcr();

  if (!kpcr)
    return nullptr;

  // KPCR::Prcb
  auto const kprcb = reinterpret_cast<uint8_t*>(kpcr)
    + g_ghv->kpcr_pcrb_offset;

  // KPCRB::CurrentThread
  PETHREAD current_thread = nullptr;
  read_guest_virtual_memory(g_ghv->system_cr3,
    kprcb + g_ghv->kprcb_current_thread_offset, &current_thread, sizeof(current_thread));

  return current_thread;
}

// 获取 the EPROCESS of the 当前 guest
PEPROCESS current_guest_eprocess() {
  // ETHREAD (KTHREAD is first field as well)
  auto const ethread = current_guest_ethread();

  if (!ethread)
    return nullptr;

  // KTHREAD::ApcState
  auto const kapc_state = reinterpret_cast<uint8_t*>(ethread)
    + g_ghv->kthread_apc_state_offset;

  // KAPC_STATE::Process
  PEPROCESS process = nullptr;
  read_guest_virtual_memory(g_ghv->system_cr3,
    kapc_state + g_ghv->kapc_state_process_offset, &process, sizeof(process));

  return process;
}

// 获取 the PID of the 当前 guest
uint64_t current_guest_pid() {
  // EPROCESS
  auto const process = reinterpret_cast<uint8_t*>(current_guest_eprocess());
  if (!process)
    return 0;

  // EPROCESS::UniqueProcessId
  uint64_t pid = 0;
  read_guest_virtual_memory(g_ghv->system_cr3,
    process + g_ghv->eprocess_unique_process_id_offset, &pid, sizeof(pid));

  return pid;
}

// 获取 the kernel CR3 of the 当前 guest
cr3 current_guest_cr3() {
  cr3 cr3;
  cr3.flags = 0;

  // EPROCESS
  auto const process = reinterpret_cast<uint8_t*>(current_guest_eprocess());
  if (!process)
    return cr3;

  // EPROCESS::DirectoryTableBase
  read_guest_virtual_memory(g_ghv->system_cr3,
    process + g_ghv->kprocess_directory_table_base_offset, &cr3, sizeof(cr3));

  return cr3;
}

// 获取 the image file name (up to 15 chars) of the 当前 guest process
bool current_guest_image_file_name(char (&name)[16]) {
  memset(name, 0, sizeof(name));

  // EPROCESS
  auto const process = reinterpret_cast<uint8_t*>(current_guest_eprocess());
  if (!process)
    return false;

  // EPROCESS::ImageFileName
  return 15 == read_guest_virtual_memory(g_ghv->system_cr3,
    process + g_ghv->eprocess_image_file_name, name, 15);
}

} // namespace hv

