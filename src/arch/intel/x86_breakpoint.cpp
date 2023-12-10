#include "breakpoint.hpp"

#define BREAKPOINT_X86_INST 0xcc
#define NOP_INST 0x90
#define BREAKPOINT_SIZE sizeof(uint64_t)
// #define BREAKPOINT_SIZE 1


// Breakpoint::Breakpoint(uintptr_t bk_addr, std::string* _label):
//     m_addr(bk_addr), m_enabled(true), m_label(_label),
//     m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)) {}

void X86BreakpointInjector::inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {

    uint8_t tmp_backup_byte = 0; // this variable will save us a system call

    debug_opts.m_memory.readRemoteAddrObj(*m_backupData.get(), m_brk_size);
    m_backupData->print();
    tmp_backup_byte = m_backupData->data()[0];
    if(tmp_backup_byte == BREAKPOINT_X86_INST) {
        m_log->critical("pid {} Breakpoint is already in place! {:x}",
            debug_opts.getPid(), m_backupData->raddr());
    }
    m_backupData->write_u8(BREAKPOINT_X86_INST);
    debug_opts.m_memory.writeRemoteAddrObj(*m_backupData.get(), m_brk_size);
    m_backupData->write_u8(tmp_backup_byte);
}

void X86BreakpointInjector::restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {

    uint8_t tmp_backup_byte; // this variable will save us a system call
    uint64_t curr_data = 0;
    Addr tmp_addr = *m_backupData.get();
    debug_opts.m_memory.readRemoteAddrObj(tmp_addr, m_brk_size);
    tmp_addr.print();
    tmp_addr.write_u8(m_backupData->read_u8());
    debug_opts.m_memory.writeRemoteAddrObj(tmp_addr, m_brk_size);
    tmp_addr.print();
}