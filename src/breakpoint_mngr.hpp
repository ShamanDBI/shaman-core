#ifndef H_BREAKPOINT_MANAGER_H
#define H_BREAKPOINT_MANAGER_H

#include <map>
#include <list>

#include "breakpoint.hpp"
#include "branch_data.hpp"
#include "witch.hpp"


class TargetDescription;
class TraceeProgram;


/**
 * @brief Manages the breakpoint for the Tracee Process
 * 
 * Problem
 * -------
 * Breakpoint handling needs to be done per tracee/process basis for
 * because of following reason
 * 
 * Lets say you start a new process call ProcA under debugger and you
 * place all the breakpoints and now the process clone(new thread) and create new
 * process called ProcB the new process all ready has the breakpoint
 * placed as they were in ProcA.
 * 
 * Now ProcB does load a new library with dlopen and we had some pending
 * breakpoints for the new library. We place the breakpoints in the ProcB
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
 * 1. When a process create a new Thread (clone syscall) inform it to breakpoint manager to add the
 *    new process ID to all the active breakpoint since the process is 
 *    forked those breakpoint opcode will already be there in new process.
 * 
 * 2. When the process has stopped executing all notify that to breakpoint
 *    manager to remote the pid from all its breakpoints
 * 
*/
class BreakpointMngr {

public:
    
    /**
     * @brief this map will have pair of module name and offset within the
     * module where the breakpoint has to be placed
     */
    std::map<std::string, std::list<Breakpoint*>> m_pending;

    /**
     * @brief Breakpoints which are alive in the tracee Process
     * 
     */
    std::map<uintptr_t, Breakpoint*> m_active_brkpnt;
    
    /**
     * @brief Branch information Cache
     * 
     * The is only valid in case of ARM Targets. This is created to implement
     * Single-Stepping feature for the Debugger
     * 
     */
    std::map<uintptr_t, std::unique_ptr<BranchData>> m_branch_info_cache;

    TargetDescription& m_target_desc;

    /**
     * @brief this is brk point is saved to restore the breakpoint once it has
     * executed, if there is no breakpoint has hit then this value should be
     * null this stores the key as thread on which the breakpoint was hit and
     * value is the breakpoint which was hit.
     */
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

    /**
     * @brief Place all the pending Breakpoint in the Tracee 
     * 
     * @param traceeProg 
     */
    void inject(TraceeProgram &traceeProg);

    Breakpoint* getBreakpointObj(uintptr_t bk_addr);

    /**
     * @brief Does the Tracee have suspended Breakpoint
     * 
     * @param tracee_pid Tracee for which we what of check for suspended breakpoint
     * @return true Thread has suspended breakpoint
     * @return false no suspended Breakpoint
     */
    bool hasSuspendedBrkPnt(pid_t tracee_pid) {
        auto sus_bkpt_iter = m_suspendedBrkPnt.find(tracee_pid);
        if (sus_bkpt_iter != m_suspendedBrkPnt.end()) {
            return true;
        }
        return false;
    }

    /**
     * @brief Place the breakpoint back in the Tracee Process
     * 
     * @param traceeProgram Process in which the Breakpoint will be restored
     */
    void restoreSuspendedBreakpoint(TraceeProgram& traceeProgram);


    /**
     * @brief Call When there is a Breakpoint hit on the Tracee
     * 
     * @param traceeProg Tracee which 
     * @param brk_addr 
     * @return BreakpointPtr 
     */
    BreakpointPtr handleBreakpointHit(TraceeProgram &traceeProg, uintptr_t brk_addr);

    void printStats();

    void setBreakpointAtAddr(TraceeProgram &traceeProg, uintptr_t brk_addr, std::string* label);

    // Currently only support ARM32 Architecture
    void placeSingleStepBreakpoint(uintptr_t brkpt_hit_addr, TraceeProgram& traceeProgram);
};

#endif