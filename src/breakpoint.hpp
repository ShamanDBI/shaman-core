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
    /**
     * @brief Insert a breakpoint into the target
     * 
     * @param debug_opts Tracee in which this breakpoint will be inserted
     * @param targetAddress The Addres at which the breakpoint will be insert
     *                  and the data of the original instruction will be copied
     * into the address object
     */
    virtual void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress) {};

    /**
     * @brief Restore the original instruction in the Tracee process
     * 
     * @param debug_opts 
     * @param targetAddress 
     */
    virtual void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress) {};
};

// its 1 but I need to fix it
#define INTEL_BREAKPOINT_INST_SIZE 8

class X86BreakpointInjector : public BreakpointInjector {

public:
    X86BreakpointInjector() : BreakpointInjector(INTEL_BREAKPOINT_INST_SIZE) {};

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
};

struct ARMBreakpointInjector : public BreakpointInjector {

    ARMBreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
};


struct ARM64BreakpointInjector : public BreakpointInjector {

    ARM64BreakpointInjector(): BreakpointInjector(4) {}

    void inject(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
    void restore(DebugOpts& debug_opts, std::unique_ptr<Addr>& targetAddress);
};


// ------------------------------- [ ARM ISA END ] ---------------------------------
enum BrkptResult {
    Success = 0,
    RemoveBkpt
};

/**
 * @brief Breakpoint which are inject in the Tracee program
 * 
 * This Interface give you ability to stop at arbitrary point in the
 * program.
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

    /// @brief offset value of the breakpoint WRT to `m_modname` base address
    uintptr_t m_offset = 0;
    
    /// @brief User friendly name of the breakpoint
    std::string m_label;

    /**
     * @brief Create Breakpoint object with friendly Name
     * 
     * This will give you a very low level control of the breakpoint interface
     * 
     * NOTE - its best to avoid setting Concrete address of the breakpoint
     * 
     * @param modname name of the module in which the breakpoint will be placed
     * @param offset offset WRT to the module base address
     * @param bk_addr Concrete Breakpoint address
     * @param _label A frendly label which will be printed in the log file
     * @param brk_type Breakpoint Type
     */
    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t bk_addr,
        std::string* _label, BreakpointType brk_type);

    Breakpoint(std::string& modname, uintptr_t offset, uintptr_t brk_addr) :
        Breakpoint(modname, offset, brk_addr, nullptr, NORMAL) {}

    Breakpoint(std::string& modname, uintptr_t offset, BreakpointType brk_type) :
        Breakpoint(modname, offset, 0, nullptr, brk_type) {}

    /**
     * @brief Construct a new Breakpoint object with the Module name and the 
     * Offset WRT to the Module base address
     * 
     * This will be most commonly used Constructor
     * 
     * @param modname Module name 
     * @param offset offset from the base of the Module 
     */
    Breakpoint(std::string& modname, uintptr_t offset) :
        Breakpoint(modname, offset, 0, nullptr, NORMAL) {}

    /// @brief Destructor
    ~Breakpoint()  { 
        reset();
    }

    void reset() {
        m_log->trace("Breakpoint at {:x} going out scope!", m_addr);
        m_addr = 0;
        m_offset = 0;
        m_hit_count = 0;
        m_enabled = false;
        m_backupData.reset();
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

    /**
     * @brief Implement the Breakpoint action code in this function
     * 
     * @param traceeProg Tracee thread which has triggered the breakpoint
     * In case of multi-threaded program breakpoint can be triggered by 
     * different threads as they share the same code.
     * 
     * @return true 
     * @return false 
     */
    virtual bool handle(TraceeProgram &traceeProg);

    /**
     * @brief Is my breakpoint enabled?
     * 
     * @return true if breakpoint is enabled
     * @return false if breakpoit is disabled
     */
    bool isEnabled() { return m_enabled; }

    /**
     * @brief Disable the breakpoint
     * 
     * @param traceeProg tracee for which this breakpoint will be disabled
     * @return int 
     */
    virtual int enable(TraceeProgram &traceeProg);

    /**
     * @brief Enable the breakpoint
     * 
     * @param traceeProg tracee for which this breakpoint will be enabled
     * @return int 
     */
    virtual int disable(TraceeProgram &traceeProg);
};


using BreakpointPtr = Breakpoint *;

#endif