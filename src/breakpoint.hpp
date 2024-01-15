#ifndef H_BREAKPOINT_H
#define H_BREAKPOINT_H

#include <vector>
#include <string>
#include <sys/ptrace.h>

#include "spdlog/spdlog.h"

#include "memory.hpp"

class DebugOpts;
class TraceeProgram;

/**
 * @brief class which is doing the actual injection dirty work
 * 
 * This is the class which you platform specific implementation for
 * placing the breakpoint should do
*/
class BreakpointInjector {

protected:

    uint8_t m_brk_size = 0;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("bkpt");

public:

    BreakpointInjector(uint8_t _brk_size):  m_brk_size(_brk_size) {};

    virtual void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {};
    virtual void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData) {};
};

// its 1 but I need to fix it
#define INTEL_BREAKPOINT_INST_SIZE 8

class X86BreakpointInjector : public BreakpointInjector {

public:
    X86BreakpointInjector() : BreakpointInjector(INTEL_BREAKPOINT_INST_SIZE) {};

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
};

// ------------------------------- ARM ISA ------------------------------------

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


struct ARMBreakpointInjector : public BreakpointInjector {

    ARMBreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
};


struct ARM64BreakpointInjector : public BreakpointInjector {

    ARM64BreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& m_backupData);
};


// ------------------------------- [ ARM ISA END ] ---------------------------------

/**
 * @brief Breakpoint which are inject in the Tracee program
 * 
 * This is another important interface of the framework
*/
class Breakpoint {

protected:

    ///@brief indicate if the breakpoint is currently enabled
    bool m_enabled = false;

    /// @brief logging the data
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("bkpt");

public:

    /// @brief different type of breakpoint
    enum BreakpointType {
        /// @brief single shot breakpoint used for collecting code coverage
        ///       Delete the breakpoint after it has been hit once
        SINGLE_SHOT = 1,

        /// @brief this breakpoint will be restored after handling it.
        NORMAL = 2,

        /// @brief this kind of breakpoint are used to single step the 
        /// breakpoint handling, and they are not restored after execution
        SINGLE_STEP = 3
    } m_type;

    /// @brief custom pointer which can be used by the handler function
    uintptr_t m_custom_ptr = 0;

    /// @brief The object which will actually inject the breakpoint
    BreakpointInjector* m_bkpt_injector;

    /// @brief this is the concrete address of the breakpoint
    // resolved address
    uintptr_t m_addr = 0;
    
    /// @brief breakpoint instruction data is stored to the memory
    /// later restored when brk pnt is hit
    std::unique_ptr<Addr> m_backupData = nullptr;
    
    // DebugOpts& m_debug_opts = nullptr;
    
    /// @brief name of the module in which this breakpoint exist
    std::string& m_modname;

    /// @brief  number of time this breakpoint was hit
    uint32_t m_hit_count = 0;

    /// @brief max hit count after which you want remove the breakpoint
    uint32_t m_max_hit_count = UINT32_MAX;

    /// @brief offset from the module
    uintptr_t m_offset = 0;

    // process id's in which this breakpoint is active
    // std::vector<pid_t> m_pids; // pid of tracee
    
    /// @brief User friendly name of the breakpoint
    std::string m_label;

    /// @brief 
    /// @param modname 
    /// @param offset 
    /// @param bk_addr 
    /// @param _label 
    /// @param brk_type 
    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t bk_addr,
        std::string* _label, BreakpointType brk_type);
    
    /// @brief 
    /// @param modname 
    /// @param offset 
    /// @param brk_addr 
    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t brk_addr) :
        Breakpoint(modname, offset, brk_addr, nullptr, NORMAL) {}

    /// @brief 
    /// @param modname 
    /// @param offset 
    /// @param brk_type 
    Breakpoint(std::string& modname, uintptr_t offset, BreakpointType brk_type) :
        Breakpoint(modname, offset, 0, nullptr, brk_type) {}

    /// @brief 
    /// @param modname 
    /// @param offset 
    Breakpoint(std::string& modname, uintptr_t offset) :
        Breakpoint(modname, offset, 0, nullptr, NORMAL) {}

    /// @brief Destructor
    ~Breakpoint()  { 
        m_log->trace("Breakpoint at {:x} going out scope!", m_addr);
        m_addr = 0;
        m_offset = 0;
        m_hit_count = 0;
        m_enabled = false;
        m_backupData.reset();
        // m_pids.clear();
    }

    Breakpoint& setInjector(BreakpointInjector* brk_pnt_injector);

    Breakpoint& makeSingleStep(uintptr_t _brkpnt_addr);

    Breakpoint& makeSingleShot();

    Breakpoint& setMaxHitCount(uint32_t max_hit_count);

    // void addPid(pid_t pid);

    /// @brief this is made virtual to capture the event in which the breakpoint
    /// is actually paced in the process memory
    virtual void setAddress(uintptr_t brkpnt_addr);

    void printDebug() {
        m_log->debug("[0x{:x}] [{}] count {} ", m_addr, m_label.c_str(), m_hit_count);
    }

    uint32_t getHitCount() { return m_hit_count; }

    bool shouldEnable();

    virtual bool handle(TraceeProgram &traceeProg);

    /// @brief Is my breakpoint enabled?
    /// @return true if enabled and false otherwise
    bool isEnabled() { return m_enabled; }

    /// @brief Disable the breakpoint
    /// @param debug_opts 
    /// @return 
    virtual int enable(TraceeProgram &traceeProg);

    /// @brief enable the Breakpoint
    /// @param debug_opts 
    /// @return 
    virtual int disable(TraceeProgram &traceeProg);
};


using BreakpointPtr = Breakpoint *;

#endif