#ifndef H_BREAKPOINT_MANAGER_H
#define H_BREAKPOINT_MANAGER_H

#include <map>
#include <list>

#include "debug_opts.hpp"
#include "breakpoint.hpp"
#include "branch_data.hpp"
#include "witch.hpp"

/**
 * Problem
 * -------
 * Breakpoint handling needs to be done per tracee/process basis for
 * because of following reason
 * 
 * Lets say you start a new process call ProcA under debugger and you
 * place all the breakpoints and now the process forks! and create new
 * process called ProcB the new process all ready has the breakpoint
 * placed as they were in ProcA.
 * 
 * Now ProcB does load a new library with dlopen and we had some pending
 * breakpoints for the new library. We place the breakpoints in the procB
 * these breakpoints and only present in ProcB so the breakpoint handlers
 * pertaining ProcB will only be registered with that particular tracee
 * only. 
 * 
 * If the breakpoint handler doesn't have the information that in which
 * all process the breakpoint is placed then when clearing the breakpoint
 * we will try to clearn the breakpoint from the process where we havn't
 * placed the breakpoint
 * 
 * Solution
 * --------
 * 
 * To have breakpoint handler at per debugger basis you need to have
 * following info:
 *  1. Each breakpoint will have information that to list of all process
 *     breakpoint is placed
 *  
 * Use cases to handle
 * -------------------
 * 
 * 1. When a process is forked inform it to breakpoint manager to add the
 *    new process ID to all the active breakpoint since the process is 
 *    forked those breakpoint opcode will already be there in new process.
 * 
 * 2. When the process has stopped executing all notify that to breakpoint
 *    manager to remote the pid from all its breakpoints
 * 
*/

class TargetDescription;
class TraceeProgram;


class BreakpointMngr {

public:
    // this map will have pair of module name and
    // offset within the module where the breakpoint 
    // has to be placed
    std::map<std::string, std::list<Breakpoint*>> m_pending;

    std::map<uintptr_t, Breakpoint*> m_active_brkpnt;
    
    std::map<uintptr_t, std::unique_ptr<BranchData>> m_branch_info_cache;

    TargetDescription& m_target_desc;

    // this is brk point is saved to restore the breakpoint
    // once it has executed, if there is no breakpoint has 
    // hit then this value should be null
    // this stores the key as thread on which the breakpoint was hit
    // and value is the breakpoint which was hit.
    std::map<pid_t, Breakpoint*> m_suspendedBrkPnt;

    ArmDisassembler* m_arm_disasm;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("bkpt");

    BreakpointMngr(TargetDescription& _target_desc) : m_target_desc(_target_desc) {
        m_arm_disasm = new ArmDisassembler(false);
    };

    // add breakpoint in format module@addr1,addr2,add3
    void parseModuleBrkPnt(std::string& brk_mod_addr);

    void addModBreakpoint(std::string& brk_mod_addr, uintptr_t mod_offset, std::string* label = nullptr);
    
    void addBrkPnt(Breakpoint* brkPtr);
    // put all the pending breakpoint in the tracee    
    void inject(DebugOpts& debug_opts);

    Breakpoint* getBreakpointObj(uintptr_t bk_addr);

    // Return true if the breakpoint was just hit on the thread on
    // which the stop event has occured
    bool hasSuspendedBrkPnt(pid_t tracee_pid) {
        auto sus_bkpt_iter = m_suspendedBrkPnt.find(tracee_pid);
        if (sus_bkpt_iter != m_suspendedBrkPnt.end()) {
            return true;
        }
        return false;
    }

    void restoreSuspendedBreakpoint(TraceeProgram& traceeProgram);

    void handleBreakpointHit(DebugOpts& debug_opts, uintptr_t brk_addr);

    void printStats();

    void setBreakpointAtAddr(DebugOpts& debug_opts, uintptr_t brk_addr, std::string* label);

    // Currently only support ARM32 Architecture
    void placeSingleStepBreakpoint(uintptr_t brkpt_hit_addr, TraceeProgram& traceeProgram);
};

#endif