#include "breakpoint_mngr.hpp"

void BreakpointMngr::addModuleBrkPnt(std::string& brk_mod_addr) {
    vector<uintptr_t> brk_offset;
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
        brk_offset.push_back(mod_offset);
    }
    m_pending.insert(make_pair(mod_name, brk_offset));
}

// put all the pending breakpoint in the tracee    
void BreakpointMngr::inject() {
    m_debug_opts->m_procMap->print();
    m_log->debug("Yeeahh... injecting all the pending Breakpoint!");

    for (auto i = m_pending.begin(); i != m_pending.end(); i++) {
        std::string mod_name = i->first;
        auto mod_base_addr = m_debug_opts->m_procMap->findModuleBaseAddr(mod_name);
        for(auto mod_offset: i->second) {
            // std::ostringstream stringStream;
            // stringStream << mod_name << "@" << mod_offset;
            // std::string copyOfStr = stringStream.str();
            char buff[100];
            snprintf(buff, sizeof(buff), "%s@%lx", mod_name.c_str(), mod_offset);
            auto x = new std::string(buff);
            setBreakpointAtAddr(mod_base_addr + mod_offset, x);
        }
    }
}

Breakpoint* BreakpointMngr::getBreakpointObj(uintptr_t bk_addr) {
    auto brk_pnt_iter = m_placed.find(bk_addr);
    if (brk_pnt_iter != m_placed.end()) {
        // breakpoint is found, its under over management
        auto brk_obj = brk_pnt_iter->second;
        return brk_obj;
    } else {
        m_log->warn("No Breakpoint object found! This is very unusual!");
        return nullptr;
    }
}

void BreakpointMngr::restoreSuspendedBreakpoint() {
    if (m_suspendedBrkPnt != nullptr) {
        m_log->debug("Restoring breakpoint and resuming execution!");
        m_suspendedBrkPnt->enable();
        m_suspendedBrkPnt = nullptr;
    }
}

void BreakpointMngr::handleBreakpointHit(uintptr_t brk_addr) {
    // PC points to the next instruction after execution
    m_log->trace("Breakpoint Hit! addr 0x{:x}", brk_addr);
    // find the breakpoint object for further processing
    auto brk_obj = getBreakpointObj(brk_addr);
    m_suspendedBrkPnt = brk_obj;
    
    brk_obj->handle();

    // m_log->debug("Brkpnt obj found!");
    // restore the value of original breakpoint instruction
    brk_obj->disable();
    
}

void BreakpointMngr::printStats() {
    m_log->info("------[ Breakpoint Stats ]-----");
    for (auto i = m_placed.begin(); i != m_placed.end(); i++) {
        auto brk_pt = i->second;
        m_log->info("{} {}", brk_pt->m_label->c_str(), brk_pt->getHitCount());
    }
    m_log->info("[------------------------------");
}

void BreakpointMngr::setBreakpointAtAddr(uintptr_t brk_addr, std::string* label) {
    Breakpoint* brk_pnt_obj = new Breakpoint(brk_addr, label);
    brk_pnt_obj->setDebugOpts(m_debug_opts);
    brk_pnt_obj->enable();
    m_placed.insert(make_pair(brk_addr, brk_pnt_obj));
}
