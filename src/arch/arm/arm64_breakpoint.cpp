#include "breakpoint.hpp"

static const uint8_t arm64_breakpoint[] = {0x00, 0x00, 0x20, 0xd4};


void ARM64BreakpointInjector::inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {
    // TODO : save the data of the breakpoint location in the buffer this
    // should have you a system call in the next breakpoint handling

    // 
    size_t buf_backup_size = 8;
    // Create shadow copy of the original instrucation
    const uint8_t* tmp_backup_byte = (uint8_t*)malloc(buf_backup_size);
    debug_opts.m_memory.readRemoteAddrObj(*m_backupData.get(), buf_backup_size);
    
    m_backupData->print();
    // storing it in the temperory variable
    memcpy((void *)tmp_backup_byte, m_backupData->data(), buf_backup_size);

    // if(tmp_backup_byte == BREAKPOINT_X86_INST) {
    //     m_log->critical("pid {} Breakpoint is already in place! {:x}",
    //         debug_opts.getPid(), m_backupData->r_addr);
    // }

    // Write the breakpoint instruction into shadow copy 
    m_backupData->copy_buffer(arm64_breakpoint, sizeof(arm64_breakpoint));

    m_backupData->print();
    // Shadow copy is commit to the process memory
    
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), 8);
    // Restore the shadow copy with the original instruction
    m_backupData->copy_buffer(tmp_backup_byte, buf_backup_size);
    free((void *)tmp_backup_byte);
}

void ARM64BreakpointInjector::restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {

    size_t brk_pnt_size = 8;

    // Addr tmp_addr = *m_backupData;
    m_backupData->print();
    // debug_opts.m_memory.read(&tmp_addr, brk_pnt_size);
    // tmp_addr.print();
    // memcpy(tmp_addr.m_data, m_backupData->m_data, tmp_addr.m_size);
    // tmp_addr.m_data[0] = m_backupData->m_data[0];
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), brk_pnt_size);
    // tmp_addr.print();
}