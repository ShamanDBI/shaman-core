#ifndef H_BRANCH_DATA_H
#define H_BRANCH_DATA_H

#include <capstone/arm.h>
#include <string>


using addr_t = size_t;

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
    addr_t m_fall_target; // branch taken when the false condition is meet
    
    BranchData();
    bool isConditional() const noexcept { return m_conditional_branch; }
    bool isDirect() const noexcept { return m_direct_branch; }
    bool isCall() const noexcept { return m_is_call; }
    bool isComputed() const noexcept {return m_is_computed ;}
    addr_t target() const { return m_target; }
};

#endif