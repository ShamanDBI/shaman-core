#include "breakpoint.hpp"


void ARMBreakpointInjector::inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {
    // TODO : save the data of the breakpoint location in the buffer this
    // should have you a system call in the next breakpoint handling

    // 
    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    if (m_backupData->raddr() & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }
    // Create shadow copy of the original instrucation
    const uint8_t* tmp_backup_byte = (uint8_t*) malloc(brk_pnt_size);
    debug_opts.m_memory.readRemoteAddrObj(*m_backupData.get(), brk_pnt_size);
    
    m_backupData->print();
    // storing it in the temperory variable
    memcpy((void *)tmp_backup_byte, m_backupData->data(), brk_pnt_size);
    
    // if(tmp_backup_byte == BREAKPOINT_X86_INST) {
        // m_log->critical("pid {} Breakpoint is already in place! {:x}",
        //     debug_opts.getPid(), m_backupData->raddr());
    // }
    // m_log->critical("pid {} {:x}", debug_opts.getPid(), m_backupData->raddr());
    
    // Write the breakpoint instruction into shadow copy 
    if (thumb_mode) {
        m_backupData->copy_buffer(arm_linux_thumb_le_breakpoint, brk_pnt_size);
    } else {
        m_backupData->copy_buffer(eabi_linux_arm_le_breakpoint, brk_pnt_size);
    }

    m_backupData->print();
    // Shadow copy is commit to the process memory
    // m_log->warn("All this point {}", brk_pnt_size);
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), 4);
    // debug_opts.m_memory.write(m_backupData, 8);
    // Restore the shadow copy with the original instruction
    m_backupData->copy_buffer(tmp_backup_byte, brk_pnt_size);
    free((void *)tmp_backup_byte);
}

void ARMBreakpointInjector::restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {

    size_t brk_pnt_size = 4;
    bool thumb_mode = false;
    if (m_backupData->raddr() & 1) {
        thumb_mode = true;
        brk_pnt_size = 2;
    }
    
    // Addr tmp_addr = *m_backupData;
    m_backupData->print();
    // debug_opts.m_memory.read(&tmp_addr, brk_pnt_size);
    // tmp_addr.print();
    // memcpy(tmp_addr.m_data, m_backupData->m_data, tmp_addr.m_size);
    // tmp_addr.m_data[0] = m_backupData->m_data[0];
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), brk_pnt_size);
    // tmp_addr.print();
}