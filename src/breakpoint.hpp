#ifndef H_BREAKPOINT_H
#define H_BREAKPOINT_H

#include <sys/ptrace.h>
#include <spdlog/spdlog.h>

#include "debug_opts.hpp"
#include "memory.hpp"

class Breakpoint {

    bool m_enabled;
    uintptr_t m_addr;

    // breakpoint instruction data is stored to the memory
    // later restored when brk pnt is hit
    Addr *m_backupData;

    // number of time this breakpoint was hit
    uint32_t m_count = 0;

    DebugOpts* m_debug_opts = nullptr;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

public:

    pid_t m_pid; // pid of tracee

    std::string *m_label;
    
    Breakpoint(uintptr_t bk_addr, std::string* _label);

    ~Breakpoint() { 
        delete m_backupData;
        delete m_label;
    }

    Breakpoint* setDebugOpts(DebugOpts* debug_opts) {
        m_debug_opts = debug_opts;
        return this;
    };
    

    void printDebug() {
        m_log->trace("BRK [0x{:x}] [{}] pid {} count {} ", m_addr, m_label->c_str(), m_pid, m_count);
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