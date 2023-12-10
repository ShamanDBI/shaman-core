#include "breakpoint.hpp"
#include "amd64_breakpoint_inject.hpp"


Breakpoint::Breakpoint(std::string& modname, uintptr_t offset, uintptr_t bk_addr,
    std::string* _label, BreakpointType brk_type) :
    m_modname(modname), m_offset(offset), m_type(brk_type) {
        if(_label == nullptr) {
            m_label = spdlog::fmt_lib::format("{}@{:x}", m_modname.c_str(), offset);
        }
        m_bkpt_injector = new X86BreakpointInjector();
    };

Breakpoint::~Breakpoint() { 
    m_log->warn("Breakpoint at {:x} going out scope!", m_addr);
    m_addr = 0;
    m_offset = 0;
    m_hit_count = 0;
    m_pids.clear();
    m_enabled = false;
    m_backupData.reset();
}

bool Breakpoint::shouldEnable() {
        if (m_type == BreakpointType::SINGLE_SHOT || 
            m_type == BreakpointType::SINGLE_STEP ) {
            return false;
        } else if(m_type == BreakpointType::NORMAL && m_hit_count > m_max_hit_count ) {
            return false;
        }

        return true;
    }

int Breakpoint::enable(DebugOpts& debug_opts) {
    m_bkpt_injector->inject(debug_opts, m_backupData);
    m_enabled = true;
    return 1;
};

int Breakpoint::disable(DebugOpts& debug_opts) {
    m_bkpt_injector->restore(debug_opts, m_backupData);
    m_enabled = false;
    return 1;
};