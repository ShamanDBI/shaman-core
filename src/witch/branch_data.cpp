#include "branch_data.hpp"


BranchData::BranchData(uintptr_t _branch_addr)
    : m_branch_addr(_branch_addr),
      m_direct_branch{false},
      m_conditional_branch{false},
      m_is_call{false},
      m_target{0}, m_fall_target{0}, m_target_brkpt(nullptr)
{
}

void BranchData::print()
{
    m_log->debug("BranchInfo 0x{:x}, T 0x{:x}, F 0x{:x} | direct {} compute {} cond {}",
                 m_branch_addr, m_target, m_fall_target,
                 m_direct_branch, m_is_computed, m_conditional_branch);
}
