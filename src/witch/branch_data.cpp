#include "branch_data.hpp"

BranchData::BranchData() :
    m_direct_branch{false},
    m_conditional_branch{false},
    m_is_call{false},
    m_target{0} {
}

