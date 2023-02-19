#ifndef H_BREAKPOINT_H
#define H_BREAKPOINT_H

#include "memory.hpp"
#include <sys/ptrace.h>
#include <spdlog/spdlog.h>

class Breakpoint {

    bool m_enabled;
    uintptr_t m_addr;
    pid_t m_pid; // pid of tracee

    // breakpoint instruction data is stored to the memory
    // later restored when brk pnt is hit
    Addr *m_backupData;
    RemoteMemory *m_remoteMemory;
    uint32_t m_count = 0;

public:

    std::string *m_label;
    
    Breakpoint(uintptr_t bk_addr, pid_t tracee_pid, std::string* _label);

    ~Breakpoint() { 
        delete m_backupData;
        delete m_remoteMemory;
        delete m_label;
    }

    void printDebug() {
        spdlog::trace("BRK [0x{:x}] [{}] pid {} count {} ", m_addr, m_label->c_str(), m_pid, m_count);
    }

    uint32_t getHitCount() {
        return m_count;
    }

    void handle() {
        m_count++;
        printDebug();
    }

    bool isEnabled() {
        return m_enabled;
    }

    virtual int enable();

    virtual int disable();
};

#endif