#ifndef H_BREAKPOINT_MANAGER_H
#define H_BREAKPOINT_MANAGER_H

#include <map>
#include <vector>

#include "modules.hpp"
#include "breakpoint.hpp"

using namespace std;


class BreakpointMngr {

    // this map will have pair of module name and
    // offset within the module where the breakpoint 
    // has to be placed
    map<string, vector<uintptr_t>> m_pending;

    map<uintptr_t, Breakpoint*> m_placed;
    ProcessMap* m_procMap;
    pid_t m_pid;

    // this is brk point is saved to restore the breakpoint
    // once it has executed, if there is no breakpoint has 
    // hit then this value should be null
    Breakpoint * m_suspendedBrkPnt = nullptr;

public:

    BreakpointMngr(pid_t tracee_pid, ProcessMap* procMap):
        m_pid(tracee_pid), m_procMap(procMap) {}

    // add breakpoint in format module@addr1,addr2,add3
    void addModuleBrkPnt(string& brk_mod_addr);

    // put all the pending breakpoint in the tracee    
    void inject();

    Breakpoint* getBreakpointObj(uintptr_t bk_addr);

    bool hasSuspendedBrkPnt() {
        return m_suspendedBrkPnt != nullptr;
    }

    void restoreSuspendedBreakpoint();

    void handleBreakpointHit(uintptr_t brk_addr);

    void printStats();

    void setBreakpointAtAddr(uintptr_t brk_addr, string* label);
};

#endif