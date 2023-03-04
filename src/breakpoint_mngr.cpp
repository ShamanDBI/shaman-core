#include "breakpoint_mngr.hpp"

void BreakpointMngr::parseModuleBrkPnt(std::string& brk_mod_addr) {
    std::list<Breakpoint*> brk_offset;
    m_log->trace("BRK {}", brk_mod_addr.c_str());
    
    auto mod_idx = brk_mod_addr.find("@");
    std::string mod_name = brk_mod_addr.substr(0, mod_idx);
    m_log->trace("Module {}", mod_name.c_str());
    
    int pnt_idx = mod_idx, prev_idx = mod_idx;

    while(pnt_idx > 0) {
        prev_idx = pnt_idx + 1;
        pnt_idx = brk_mod_addr.find(",", prev_idx);
        uint64_t mod_offset = 0;
        if(pnt_idx > 0)
            mod_offset = stoi(brk_mod_addr.substr(prev_idx, pnt_idx - prev_idx), 0, 16);
        else 
            mod_offset = stoi(brk_mod_addr.substr(prev_idx), 0, 16);
        m_log->trace("  Off {:x}", mod_offset);

        brk_offset.push_back(new Breakpoint(mod_name, mod_offset));
    }
    
    m_pending[mod_name] = brk_offset;
}

// put all the pending breakpoint in the tracee    
void BreakpointMngr::inject(DebugOpts* debug_opts) {
    debug_opts->m_procMap->print();
    m_log->debug("Yeeahh... injecting all the pending Breakpoint!");

    for (auto pend_iter = m_pending.cbegin(); pend_iter != m_pending.cend();) {
        
        // find the module base address
        std::string mod_name = pend_iter->first;
        auto mod_base_addr = debug_opts->m_procMap->findModuleBaseAddr(mod_name);

        // iterate over all the breakpoint for that module
        // for(auto brkpnt_obj: pend_iter->second) {
        auto brk_pending_objs = pend_iter->second;
        while (!brk_pending_objs.empty()) {
            Breakpoint* brkpnt_obj = brk_pending_objs.back();
            uintptr_t brk_addr = mod_base_addr + brkpnt_obj->m_offset;
            spdlog::critical("Brk addr : {:x}", brk_addr);
            brkpnt_obj->setAddress(brk_addr);
            brkpnt_obj->enable(debug_opts);
            brkpnt_obj->addPid(debug_opts->getPid());

            m_active_brkpnt[brk_addr] = brkpnt_obj;
            brk_pending_objs.pop_back();
        }
        pend_iter = m_pending.erase(pend_iter);    // or "it = m.erase(it)" since C++11
    }
}

Breakpoint* BreakpointMngr::getBreakpointObj(uintptr_t bk_addr) {
    auto brk_pnt_iter = m_active_brkpnt.find(bk_addr);
    if (brk_pnt_iter != m_active_brkpnt.end()) {
        // breakpoint is found, its under over management
        auto brk_obj = brk_pnt_iter->second;
        return brk_obj;
    } else {
        m_log->warn("No Breakpoint object found! This is very unusual!");
        return nullptr;
    }
}

void BreakpointMngr::restoreSuspendedBreakpoint(DebugOpts* debug_opts) {
    if (m_suspendedBrkPnt != nullptr) {
        m_log->debug("Restoring breakpoint and resuming execution!");
        m_suspendedBrkPnt->enable(debug_opts);
        m_suspendedBrkPnt = nullptr;
    }
}


void BreakpointMngr::handleBreakpointHit(DebugOpts* debug_opts, uintptr_t brk_addr) {
    // PC points to the next instruction after execution
    m_log->trace("Breakpoint Hit! addr 0x{:x}", brk_addr);
    // find the breakpoint object for further processing
    auto brk_obj = getBreakpointObj(brk_addr);
    m_suspendedBrkPnt = brk_obj;
    
    bool should_restore = brk_obj->handle(debug_opts);

    // m_log->debug("Brkpnt obj found!");
    // restore the value of original breakpoint instruction
    brk_obj->disable(debug_opts);
    
}

void BreakpointMngr::printStats() {
    m_log->info("------[ Breakpoint Stats ]-----");
    for (auto i = m_active_brkpnt.begin(); i != m_active_brkpnt.end(); i++) {
        auto brk_pt = i->second;
        m_log->info("{} {}", brk_pt->m_label.c_str(), brk_pt->getHitCount());
    }
    m_log->info("[------------------------------");
}
