#include "config.hpp"
#include "breakpoint.hpp"
#include "debug_opts.hpp"
#include "tracee.hpp"

Breakpoint::Breakpoint(
    std::string &modname, uintptr_t offset, uintptr_t bk_addr,
    std::string *_label, BreakpointType brk_type)
    : m_modname(modname), m_offset(offset), m_type(brk_type)
{
    if (_label == nullptr)
    {
        m_label = spdlog::fmt_lib::format("{}@{:x}", m_modname.c_str(), offset);
    }

#if defined(SUPPORT_ARCH_X86)
    m_bkpt_injector = new X86BreakpointInjector();
#elif defined(SUPPORT_ARCH_ARM)
    m_bkpt_injector = new ARMBreakpointInjector();
#elif defined(SUPPORT_ARCH_ARM64)
    m_bkpt_injector = new ARM64BreakpointInjector();
#else
    log->error("No Architecture is specified")
        exit(-1);
#endif
}

// Breakpoint::~Breakpoint() {
//     m_log->trace("Breakpoint at {:x} going out scope!", m_addr);
//     m_addr = 0;
//     m_offset = 0;
//     m_hit_count = 0;
//     m_enabled = false;
//     m_backupData.reset();
//     // m_pids.clear();
// }

Breakpoint &Breakpoint::setInjector(BreakpointInjector *brk_pnt_injector)
{
    m_bkpt_injector = brk_pnt_injector;
    return *this;
}

Breakpoint &Breakpoint::makeSingleStep(uintptr_t _brkpnt_addr)
{
    m_type = BreakpointType::SINGLE_STEP;
    setAddress(_brkpnt_addr);
    return *this;
}

Breakpoint &Breakpoint::makeSingleShot()
{
    m_type = BreakpointType::SINGLE_SHOT;
    return *this;
}

Breakpoint &Breakpoint::setMaxHitCount(uint32_t max_hit_count)
{
    m_max_hit_count = max_hit_count;
    return *this;
}

void Breakpoint::setAddress(uintptr_t brkpnt_addr)
{
    // set concrete offset of breakpoint in process memory space
    m_addr = brkpnt_addr;
    m_backupData = std::unique_ptr<Addr>(new Addr(m_addr, 8));
}

bool Breakpoint::shouldEnable()
{
    if (m_type == BreakpointType::SINGLE_SHOT ||
        m_type == BreakpointType::SINGLE_STEP)
    {
        return false;
    }
    else if (m_type == BreakpointType::NORMAL && m_hit_count > m_max_hit_count)
    {
        return false;
    }

    return true;
}

bool Breakpoint::handle(TraceeProgram &traceeProg)
{
    m_hit_count++;
    return true;
}

int Breakpoint::enable(TraceeProgram &traceeProg)
{
    m_bkpt_injector->inject(traceeProg.getDebugOpts(), m_backupData);
    m_enabled = true;
    return 1;
};

int Breakpoint::disable(TraceeProgram &traceeProg)
{
    m_bkpt_injector->restore(traceeProg.getDebugOpts(), m_backupData);
    m_enabled = false;
    return 1;
};