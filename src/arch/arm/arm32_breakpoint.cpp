#include "breakpoint.hpp"
// #include 
#define BREAKPOINT_X86_INST 0xcc
#define NOP_INST 0x90
#define BREAKPOINT_SIZE sizeof(uint64_t)
// #define BREAKPOINT_SIZE 1


// Breakpoint::Breakpoint(uintptr_t bk_addr, std::string* _label):
//     m_addr(bk_addr), m_enabled(true), m_label(_label),
//     m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)) {}

void ARMBreakpointInjector::inject(DebugOpts& debug_opts, Addr *m_backupData) {
    // TODO : save the data of the breakpoint location in the buffer this
    // should have you a system call in the next breakpoint handling

    // 
    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    if (m_backupData->r_addr & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }

    // Create shadow copy of the original instrucation
    void* tmp_backup_byte = malloc(brk_pnt_size);
    debug_opts.m_memory.read(m_backupData, brk_pnt_size);
    
    m_backupData->print();
    // storing it in the temperory variable
    memcpy(tmp_backup_byte, m_backupData->m_data, brk_pnt_size);
    
    // if(tmp_backup_byte == BREAKPOINT_X86_INST) {
    //     m_log->critical("pid {} Breakpoint is already in place! {:x}",
    //         debug_opts.getPid(), m_backupData->r_addr);
    // }
    
    // Write the breakpoint instruction into shadow copy 
    if (thumb_mode) {
        memcpy(m_backupData->m_data, &arm_linux_thumb_le_breakpoint, brk_pnt_size);
    } else {
        memcpy(m_backupData->m_data, &eabi_linux_arm_le_breakpoint, brk_pnt_size);
    }
    m_backupData->print();
    // Shadow copy is commit to the process memory
    debug_opts.m_memory.write(m_backupData, brk_pnt_size);
    // Restore the shadow copy with the original instruction
    memcpy(m_backupData->m_data, tmp_backup_byte, brk_pnt_size);
    free(tmp_backup_byte);
}

void ARMBreakpointInjector::restore(DebugOpts& debug_opts, Addr *m_backupData) {

    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    if (m_backupData->r_addr & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }
    
    // Addr tmp_addr = *m_backupData;
    m_backupData->print();
    // debug_opts.m_memory.read(&tmp_addr, brk_pnt_size);
    // tmp_addr.print();
    // memcpy(tmp_addr.m_data, m_backupData->m_data, tmp_addr.m_size);
    // tmp_addr.m_data[0] = m_backupData->m_data[0];
    debug_opts.m_memory.write(m_backupData, brk_pnt_size);
    // tmp_addr.print();
}