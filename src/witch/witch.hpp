#ifndef H_ARM_DISASSEMBLER_H
#define H_ARM_DISASSEMBLER_H

#include <capstone/capstone.h>

#include "debug_opts.hpp"
#include "branch_data.hpp"

class ARMInstAnalyzer;

/**
 * @brief Disassembler for ARM 32-bit architecture
 * 
 * Its primarilty used to figure out the branch destination of the
 * instruction
*/
class ArmDisassembler {

    csh m_handle = {};
    bool m_is_thumb = false;
    ARMInstAnalyzer* m_inst_analyzer;
    cs_insn* _tmp_inst_info;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");

public:

    ArmDisassembler(bool is_thumb_mode);

    ~ArmDisassembler();

    // void iter_basic_block(cs_insn *insn);

    void disassSingleInst(const uint8_t *data, uint64_t vaddr, cs_insn* insn);

    /// @brief Disassemble the instruction to figure out the branch destination
    /// @param data [in] binary data you want to disassemble
    /// @param branchInfo [out] this class will have filled with the branch destination
    /// @param debug_opts [in] to probe the Tracee Process for register information
    void getBranchInfo(const uint8_t *data, BranchData& branchInfo, DebugOpts& debug_opts);

    void disass(const uint8_t *data, size_t len, uint64_t vaddr);
};

#endif