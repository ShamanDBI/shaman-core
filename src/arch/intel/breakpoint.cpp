#include "breakpoint.hpp"

#define BREAKPOINT_INST 0xcc;
#define NOP_INST 0x90;
#define BREAKPOINT_SIZE sizeof(uint64_t)


Breakpoint::Breakpoint(uintptr_t bk_addr, pid_t tracee_pid, std::string* _label): m_addr(bk_addr),
    m_enabled(true), m_pid(tracee_pid), m_label(_label),
    m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)),
    m_remoteMemory(new RemoteMemory(tracee_pid)) {}

int Breakpoint::enable() {

    uint8_t tmp_backup_byte; // this variable will save us a system call

    m_remoteMemory->read(m_backupData, BREAKPOINT_SIZE);
    
    tmp_backup_byte = m_backupData->addr[0];
    m_backupData->addr[0] = BREAKPOINT_INST;
    m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
    m_backupData->addr[0] = tmp_backup_byte;
    
    m_enabled = true;
    return 1;
}

int Breakpoint::disable() {
    m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
    m_backupData->clean();
    m_enabled = false;
    return 1;
}