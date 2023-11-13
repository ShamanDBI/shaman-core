#include "breakpoint.hpp"

#define BREAKPOINT_X86_INST 0xcc
#define NOP_INST 0x90
#define BREAKPOINT_SIZE sizeof(uint64_t)
// #define BREAKPOINT_SIZE 1


// Breakpoint::Breakpoint(uintptr_t bk_addr, std::string* _label):
//     m_addr(bk_addr), m_enabled(true), m_label(_label),
//     m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)) {}

void ARMBreakpointInjector::inject(DebugOpts& debug_opts, Addr *m_backupData) {

    uint32_t tmp_backup_byte = 0; // this variable will save us a system call
    size_t brk_pnt_size = 4;
    bool thumb_mode = false;

    if (m_backupData->r_addr & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }

    debug_opts.m_memory.read(m_backupData, m_brk_size);
    m_backupData->print();
    tmp_backup_byte = m_backupData->m_data[0];
    if(tmp_backup_byte == BREAKPOINT_X86_INST) {
        m_log->critical("pid {} Breakpoint is already in place! {:x}",
            debug_opts.getPid(), m_backupData->r_addr);
    }
    if (thumb_mode) {
        memcpy(m_backupData->m_data, &arm_linux_thumb_le_breakpoint, brk_pnt_size);
    } else {
        memcpy(m_backupData->m_data, &arm_linux_arm_le_breakpoint, brk_pnt_size);
    }

    m_backupData->m_data[0] = BREAKPOINT_X86_INST;
    debug_opts.m_memory.write(m_backupData, m_brk_size);
    m_backupData->m_data[0] = tmp_backup_byte;
}

void ARMBreakpointInjector::restore(DebugOpts& debug_opts, Addr *m_backupData) {

    uint8_t tmp_backup_byte; // this variable will save us a system call
    uint64_t curr_data = 0;
    Addr tmp_addr = *m_backupData;
    debug_opts.m_memory.read(&tmp_addr, m_brk_size);
    tmp_addr.print();
    tmp_addr.m_data[0] = m_backupData->m_data[0];
    debug_opts.m_memory.write(&tmp_addr, m_brk_size);
    tmp_addr.print();
}