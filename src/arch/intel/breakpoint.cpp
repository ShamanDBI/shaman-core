#include "breakpoint.hpp"

#define BREAKPOINT_INST 0xcc;
#define NOP_INST 0x90;
#define BREAKPOINT_SIZE sizeof(uint64_t)
// #define BREAKPOINT_SIZE 1


// Breakpoint::Breakpoint(uintptr_t bk_addr, std::string* _label):
//     m_addr(bk_addr), m_enabled(true), m_label(_label),
//     m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)) {}

int Breakpoint::enable(DebugOpts* debug_opts) {

    uint8_t tmp_backup_byte; // this variable will save us a system call

    debug_opts->m_memory->read(m_backupData, BREAKPOINT_SIZE);
    m_backupData->print();
    tmp_backup_byte = m_backupData->m_data[0];
    m_backupData->m_data[0] = BREAKPOINT_INST;
    debug_opts->m_memory->write(m_backupData, BREAKPOINT_SIZE);
    m_backupData->m_data[0] = tmp_backup_byte;
    m_enabled = true;
    return 1;
}

int Breakpoint::disable(DebugOpts* debug_opts) {

    uint8_t tmp_backup_byte; // this variable will save us a system call
    uint64_t curr_data = 0;
    Addr tmp_addr = *m_backupData;
    debug_opts->m_memory->read(&tmp_addr, BREAKPOINT_SIZE);
    tmp_addr.print();
    tmp_addr.m_data[0] = m_backupData->m_data[0];
    // m_backupData->m_data[0] = BREAKPOINT_INST;
    debug_opts->m_memory->write(&tmp_addr, BREAKPOINT_SIZE);
    tmp_addr.print();
    /*
    // Old Impl
    debug_opts->m_memory->write(m_backupData, BREAKPOINT_SIZE);
    m_backupData->clean();
    */
    m_enabled = false;
    return 1;
}