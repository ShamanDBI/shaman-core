#ifndef H_BREAKPOINT_H
#define H_BREAKPOINT_H

#include <vector>
#include <string>
#include <sys/ptrace.h>

#include "spdlog/spdlog.h"

#include "debug_opts.hpp"
#include "memory.hpp"

class BreakpointInjector {

protected:

    uint8_t m_brk_size = 0;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

public:

    BreakpointInjector(uint8_t _brk_size):  m_brk_size(_brk_size) {};

    virtual void inject(DebugOpts& debug_opts, Addr *m_backupData) {};
    virtual void restore(DebugOpts& debug_opts, Addr *m_backupData) {};
};

// its 1 but I need to fix it
#define INTEL_BREAKPOINT_INST_SIZE 8

class X86BreakpointInjector : public BreakpointInjector {

public:
    X86BreakpointInjector() : BreakpointInjector(INTEL_BREAKPOINT_INST_SIZE) {};

    void inject(DebugOpts& debug_opts, Addr *m_backupData);
    void restore(DebugOpts& debug_opts, Addr *m_backupData);
};

#define BREAKINST_ARM	0xe7f001f0
#define BREAKINST_THUMB	0xde01

/* Under ARM GNU/Linux the traditional way of performing a breakpoint
   is to execute a particular software interrupt, rather than use a
   particular undefined instruction to provoke a trap. Upon exection
   of the software interrupt the kernel stops the inferior with a
   SIGTRAP, and wakes the debugger.  */

static const uint8_t arm_linux_arm_le_breakpoint[] = { 0x01, 0x00, 0x9f, 0xef };

static const uint8_t arm_linux_arm_be_breakpoint[] = { 0xef, 0x9f, 0x00, 0x01 };

/* However, the EABI syscall interface (new in Nov. 2005) does not look at
   the operand of the swi if old-ABI compatibility is disabled.  Therefore,
   use an undefined instruction instead.  This is supported as of kernel
   version 2.5.70 (May 2003), so should be a safe assumption for EABI
   binaries.  */

static const uint8_t eabi_linux_arm_le_breakpoint[] = { 0xf0, 0x01, 0xf0, 0xe7 };

static const uint8_t eabi_linux_arm_be_breakpoint[] = { 0xe7, 0xf0, 0x01, 0xf0 };

/* All the kernels which support Thumb support using a specific undefined
   instruction for the Thumb breakpoint.  */

static const uint8_t arm_linux_thumb_be_breakpoint[] = {0xde, 0x01};

static const uint8_t arm_linux_thumb_le_breakpoint[] = {0x01, 0xde};

/* Because the 16-bit Thumb breakpoint is affected by Thumb-2 IT blocks,
   we must use a length-appropriate breakpoint for 32-bit Thumb
   instructions.  See also thumb_get_next_pc.  */

static const uint8_t arm_linux_thumb2_be_breakpoint[] = { 0xf7, 0xf0, 0xa0, 0x00 };

static const uint8_t arm_linux_thumb2_le_breakpoint[] = { 0xf0, 0xf7, 0x00, 0xa0 };


class ARMBreakpointInjector : public BreakpointInjector {
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
public:
    ARMBreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, Addr *m_backupData);
    void restore(DebugOpts& debug_opts, Addr *m_backupData);
};


class ARM64BreakpointInjector : public BreakpointInjector {
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
public:
    ARM64BreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, Addr *m_backupData);
    void restore(DebugOpts& debug_opts, Addr *m_backupData);
};


struct Breakpoint {

    enum BreakpointType {
        // single shot breakpoint used for collecting code coverage
        // Delete the breakpoint after it has been hit once
        SINGLE_SHOT = 1,

        // this breakpoint will be restored after handling it.
        NORMAL = 2,

        // this kind of breakpoint are used to single step the 
        // breakpoint handling, and they are not restored after execution
        SINGLE_STEP = 3
    } m_type;

    BreakpointInjector* m_bkpt_injector;

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
    uint32_t m_hit_count = 0;

    // max hit count after which you want remove the breakpoint
    uint32_t m_max_hit_count = UINT32_MAX;

    // offset from the module
    uintptr_t m_offset = 0;

    // process id's in which this breakpoint is active
    std::vector<pid_t> m_pids; // pid of tracee

    std::string m_label;

    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t bk_addr,
        std::string* _label, BreakpointType brk_type);
    
    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t brk_addr) :
        Breakpoint(modname, offset, brk_addr, nullptr, NORMAL) {}

    Breakpoint(std::string& modname, uintptr_t offset, BreakpointType brk_type) :
        Breakpoint(modname, offset, 0, nullptr, brk_type) {}

    Breakpoint(std::string& modname, uintptr_t offset) :
        Breakpoint(modname, offset, 0, nullptr, NORMAL) {}

    ~Breakpoint() { 
        m_log->warn("Breakpoint at {:x} going out scope!", m_addr);
        delete m_backupData;
        // delete m_label;
    }

    Breakpoint& setInjector(BreakpointInjector* brk_pnt_injector) {
        m_bkpt_injector = brk_pnt_injector;
        return *this;
    }

    Breakpoint& makeSingleStep(uintptr_t _brkpnt_addr) {
        m_type = BreakpointType::SINGLE_STEP;
        setAddress(_brkpnt_addr);
        return *this;
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
        m_backupData = new Addr(m_addr, 8);
    }

    void printDebug() {
        m_log->debug("BRK [0x{:x}] [{}] count {} ", m_addr, m_label.c_str(), m_hit_count);
    }

    uint32_t getHitCount() {
        return m_hit_count;
    }

    bool shouldEnable() {
        if (m_type == BreakpointType::SINGLE_SHOT || 
            m_type == BreakpointType::SINGLE_STEP ) {
            return false;
        } else if(m_type == BreakpointType::NORMAL && m_hit_count > m_max_hit_count ) {
            return false;
        }

        return true;
    }

    virtual bool handle(DebugOpts& debug_opts) {
        m_hit_count++;
        return true;
    }

    bool isEnabled() {
        return m_enabled;
    }

    virtual int enable(DebugOpts& debug_opts);

    virtual int disable(DebugOpts& debug_opts);
};

#endif