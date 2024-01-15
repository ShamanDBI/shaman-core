#ifndef H_BRANCH_DATA_H
#define H_BRANCH_DATA_H

#include <capstone/arm.h>
#include <string>
#include <memory>
#include "spdlog/spdlog.h"
#include "breakpoint.hpp"

// using addr_t = uintptr_t;
class Breakpoint;

/**
 * @brief This class contains branch destination of Instruction
 * 
 * This is used to implement Single-Stepping in ARM 32 Architecture
*/
struct BranchData {

    // we don't need compulation to take the branch
    bool m_direct_branch;

    bool m_is_call;
    
    // the branch will be taken based on condition
    bool m_conditional_branch;
    
    // this is set when to get the target
    bool m_is_computed; 
    
    uintptr_t m_branch_addr; // Address of the Branch Instruction 
    
    uintptr_t m_target; // branch taken when the true condition is meet
    
    // branch taken when the false condition is meet, also called
    // as fall-through branch
    uintptr_t m_fall_target;

    std::unique_ptr<Breakpoint> m_target_brkpt;
    std::unique_ptr<Breakpoint> m_fall_target_brkpt;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");
    
    BranchData(uintptr_t _branch_addr);

    BranchData(const BranchData&) = delete;
    BranchData& operator=(const BranchData&) = delete;
    // ~BranchData() = def;

    bool isConditional() { return m_conditional_branch; }
    bool isDirect() { return m_direct_branch; }
    bool isCall() { return m_is_call; }
    bool isComputed() { return m_is_computed; }
    void print();

    uintptr_t addr() { return m_branch_addr; };
    uintptr_t target() { return m_target; }
    uintptr_t fall_addr() { return m_fall_target; }
};

#endif