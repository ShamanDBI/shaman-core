#ifndef H_ARM_DISASSEMBLER_H
#define H_ARM_DISASSEMBLER_H

#include <capstone/capstone.h>
#include "inst_analyzer.hpp"
#include "branch_data.hpp"

class DebugOpts;

class ArmDisassembler {

    csh m_handle = {};
    bool m_is_thumb = false;
    ARMInstAnalyzer* m_inst_analyzer;
    cs_insn* _tmp_inst_info;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");

public:

    ArmDisassembler(bool is_thumb_mode);

    ~ArmDisassembler();

    void iter_basic_block(cs_insn *insn);

    void disassSingleInst(const uint8_t *data, uint64_t vaddr, cs_insn* insn);

    void getBranchInfo(const uint8_t *data, BranchData& branchInfo, DebugOpts& debug_opts);

    void disass(const uint8_t *data, size_t len, uint64_t vaddr);
};

#endif