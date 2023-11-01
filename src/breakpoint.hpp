#ifndef H_BREAKPOINT_H
#define H_BREAKPOINT_H

#include <vector>
#include <string>
#include <sys/ptrace.h>
#include <spdlog/spdlog.h>
#include "spdlog/spdlog.h"

#include "debug_opts.hpp"
#include "memory.hpp"


#define BREAKPOINT_SIZE sizeof(uint64_t)

struct BreakpointInjector {
    
    uint8_t m_brk_size = 0;

    virtual void inject(DebugOpts& debug_opts, Addr *m_backupData) = 0;
    virtual void restore(DebugOpts& debug_opts, Addr *m_backupData) = 0;
};

struct X86BreakpointInjector : BreakpointInjector {
    uint8_t m_brk_size = 1;

    X86BreakpointInjector() {
    }

    void inject(DebugOpts& debug_opts, Addr *m_backupData);
    void restore(DebugOpts& debug_opts, Addr *m_backupData);
};

struct ARMBreakpointInjector : BreakpointInjector {

    #define BREAKINST_ARM	0xe7f001f0
    #define BREAKINST_THUMB	0xde01
    
    uint8_t m_brk_size = 1;
    void inject(DebugOpts& debug_opts, Addr *m_backupData);
    void restore(DebugOpts& debug_opts, Addr *m_backupData);
};


class Breakpoint {

public:
    enum BreakpointType {
        // single shot breakpoint used for collecting code coverage
        // Delete the breakpoint after it has been hit once
        SINGLE_SHOT = 1,

        //
        NORMAL
    } m_type;

    std::shared_ptr<BreakpointInjector> m_bkpt_injector;

    bool m_enabled = false;
    
    // this is the concrete address of the breakpoint
    // resolved address
    uintptr_t m_addr = 0;
    
    // breakpoint instruction data is stored to the memory
    // later restored when brk pnt is hit
    Addr *m_backupData = nullptr;
    
    // DebugOpts& m_debug_opts = nullptr;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
    
    // name of the module in which this breakpoint exist
    std::string& m_modname;

    // number of time this breakpoint was hit
    uint32_t m_count = 0;

    // max hit count after which you want remove the breakpoint
    uint32_t m_max_hit_count = UINT32_MAX;

    // offset from the module
    uintptr_t m_offset = 0;

    // process id's in which this breakpoint is active
    std::vector<pid_t> m_pids; // pid of tracee

    std::string m_label;

    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t bk_addr,
        std::string* _label, BreakpointType brk_type) :
        m_modname(modname), m_offset(offset), m_type(brk_type) {
            if(_label == nullptr) {
                m_label = spdlog::fmt_lib::format("{}@{:x}", m_modname.c_str(), offset);
            }
        }
    
    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t brk_addr) :
        Breakpoint(modname, offset, brk_addr, nullptr, NORMAL) {}

    Breakpoint(std::string& modname, uintptr_t offset, BreakpointType brk_type) :
        Breakpoint(modname, offset, 0, nullptr, brk_type) {}

    Breakpoint(std::string& modname, uintptr_t offset) :
        Breakpoint(modname, offset, 0, nullptr, NORMAL) {}

    ~Breakpoint() { 
        m_log->warn("Breakpoint : going out out scope!");
        delete m_backupData;
        // delete m_label;
    }

    Breakpoint& makeSingleShot() {
        m_type = BreakpointType::SINGLE_SHOT;
        return *this;
    }

    Breakpoint& setMaxHitCount(uint32_t max_hit_count) {
        m_max_hit_count = max_hit_count;
        return *this;
    }

    void addPid(pid_t pid) {
        m_pids.push_back(pid);
    }

    void addBackupData(Addr* backup_data) {
        m_backupData = backup_data;
    }

    virtual void setAddress(uintptr_t brkpnt_addr) {
        // set concrete offset of breakpoint in process memory space
        m_addr = brkpnt_addr;
        m_backupData = new Addr(m_addr, BREAKPOINT_SIZE);
    }

    void printDebug() {
        m_log->debug("BRK [0x{:x}] [{}] count {} ", m_addr, m_label.c_str(), m_count);
    }

    uint32_t getHitCount() {
        return m_count;
    }

    bool shouldEnable() {
        if (m_type == BreakpointType::SINGLE_SHOT) {
            return false;
        } else {
            return true;
        }
    }

    virtual bool handle(DebugOpts& debug_opts) {
        m_count++;
        // printDebug();
        return true;
    }

    bool isEnabled() {
        return m_enabled;
    }

    virtual int enable(DebugOpts& debug_opts) {
        m_bkpt_injector->inject(debug_opts, m_backupData);
        m_enabled = true;
        return 1;
    };

    virtual int disable(DebugOpts& debug_opts) {
        m_bkpt_injector->restore(debug_opts, m_backupData);
        m_enabled = false;
        return 1;
    };
};

#endif