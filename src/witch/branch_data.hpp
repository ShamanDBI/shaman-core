#ifndef H_BRANCH_DATA_H
#define H_BRANCH_DATA_H

#include <capstone/arm.h>
#include <string>
#include "spdlog/spdlog.h"

using addr_t = uintptr_t;

struct BranchData {

    // we don't need compulation to take the branch
    bool m_direct_branch;

    bool m_is_call;
    
    // the branch will be taken based on condition
    bool m_conditional_branch;
    
    // this is set when to get the target
    bool m_is_computed; 
    
    addr_t m_branch_addr; // Address of the Branch Instruction 
    
    addr_t m_target; // branch taken when the true condition is meet
    
    // branch taken when the false condition is meet, also called
    // as fall-through branch
    addr_t m_fall_target;

    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");
    
    BranchData(addr_t _branch_addr);

    bool isConditional() { return m_conditional_branch; }
    bool isDirect() { return m_direct_branch; }
    bool isCall() { return m_is_call; }
    bool isComputed() { return m_is_computed; }
    void print();

    addr_t addr() { return m_branch_addr; };
    addr_t target() { return m_target; }
    addr_t fall_addr() { return m_fall_target; }
};

#endif