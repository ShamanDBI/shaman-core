#ifndef H_ARM_DISASSEMBLER_H
#define H_ARM_DISASSEMBLER_H

#include <capstone/capstone.h>
#include "inst_analyzer.hpp"


class TargetDescription;

class ArmDisassembler {

    csh m_handle = {};
    bool m_is_thumb = false;
    ARMInstAnalyzer m_inst_analyzer;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("disasm");

public:

    ArmDisassembler(TargetDescription& m_target_desc);

    ~ArmDisassembler() { cs_close(&m_handle); }

    void iter_basic_block(cs_insn *insn);

    cs_insn * disass_single_inst(const uint8_t *data, uint64_t len, uint64_t vaddr);

    void disass(const uint8_t *data, uint64_t len, uint64_t vaddr);
};

#endif