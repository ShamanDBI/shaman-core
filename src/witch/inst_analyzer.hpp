#ifndef H_ARM_INST_ANALYZER_H
#define H_ARM_INST_ANALYZER_H

#include <vector>
#include <capstone/capstone.h>
#include "branch_data.hpp"
#include "debug_opts.hpp"


class ARMInstAnalyzer {
    
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");

public:

    /**
     * return true if instruction is a branch
     */
    bool isBranch(const cs_insn *inst) const noexcept;

    /**
     * return true if instruction is conditional, note that conditional
     * instructions inside IT block context info that is not available here.
     */
    bool isConditional(cs_insn *inst) const;

    bool isDirectBranch(cs_insn *inst) const;

    bool getBranchDest(cs_insn* inst, BranchData& branch_info, DebugOpts& debug_opts);

    // valid only for ARM architecture which has two modes Thumb & ARM
    // void changeModeTo();

    const std::string conditionCodeToString(const arm_cc &condition) const;
    
    void prettyPrintCapstoneInst(const csh &handle, cs_insn *inst, bool details_enabled);

    bool getBranchDest(cs_insn* inst);
};


#endif