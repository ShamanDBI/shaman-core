#include <capstone/capstone.h>
#include "witch.hpp"
#include "inst_analyzer.hpp"


ArmDisassembler::ArmDisassembler(bool is_thumb_mode) {
    cs_mode mode = CS_MODE_THUMB;
    m_inst_analyzer = new ARMInstAnalyzer();
    if (!is_thumb_mode)
    {
        mode = CS_MODE_ARM;
        m_is_thumb = is_thumb_mode;
    }

    if (cs_open(CS_ARCH_ARM, mode, &m_handle) != CS_ERR_OK)
    {
        m_log->error("Apparently no support for ARM in capstone.lib");
    }

    _tmp_inst_info = cs_malloc(m_handle);

    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
}

ArmDisassembler::~ArmDisassembler() {
    cs_close(&m_handle);
    cs_free(_tmp_inst_info, 1);
    delete m_inst_analyzer;
}

    /*
void ArmDisassembler::iter_basic_block(cs_insn *insn) {
    std::vector<BasicBlock *> all_ident_bb;
    BasicBlock* curr_bb;
    uint64_t bb_id = 0;
    bool bb_start = true;
    uint16_t bb_size = 0;
    bb_size += insn->size;
    // BranchData* branch_info = new BranchData();

    if(bb_start) {
        m_log->trace("--------------------------------------------------\n");
        curr_bb = new BasicBlock(bb_id, insn);
        bb_id++;
        bb_start = false;
    }

    if(0) {
    // if(m_inst_analyzer->getBranchDest(insn, *branch_info, nullptr)) {
        m_inst_analyzer->prettyPrintCapstoneInst(m_handle, insn, true);
        m_log->trace("BB Size = %ld\n", curr_bb->size());
        all_ident_bb.push_back(curr_bb);
        bb_start = true;
    } else {
        m_inst_analyzer->prettyPrintCapstoneInst(m_handle, insn, false);
    }
    curr_bb->append(insn);
    m_log->trace("No of Basic Block : %ld\n", all_ident_bb.size());
}
    */

void ArmDisassembler::disassSingleInst(const uint8_t *data, uint64_t vaddr, cs_insn* insn) {

    size_t inst_len = 4;

    if(m_is_thumb) {
        inst_len = 2;
    }
    _tmp_inst_info = cs_malloc(m_handle);
    
    bool should_cont = cs_disasm_iter(m_handle, &data, &inst_len, &vaddr, _tmp_inst_info);
    // if (!should_cont) {
    //     m_log->error("Invalid disassembly of Instruction");
    // }
    // return insn;
}

void ArmDisassembler::getBranchInfo(const uint8_t* data, BranchData& branchInfo, DebugOpts& debug_opts) {
    disassSingleInst(data, branchInfo.addr(), _tmp_inst_info);
    m_inst_analyzer->prettyPrintCapstoneInst(m_handle, _tmp_inst_info, true);
    m_inst_analyzer->getBranchDest(_tmp_inst_info, branchInfo, debug_opts);
}

void ArmDisassembler::disass(const uint8_t *data, size_t len, uint64_t vaddr)
{
    cs_insn *insn = cs_malloc(m_handle);
    const uint8_t* tmp_data = data;
    size_t tmp_len = len;
    bool cont_disasm = true;

    while(cont_disasm) {
        cont_disasm = cs_disasm_iter(m_handle, &tmp_data, &tmp_len, &vaddr, insn);
    }

    cs_free(insn, 1);
}


#ifdef DISS_TEST

#define ARM_CODE "\x00\x48\x2d\xe9\x04\xb0\x8d\xe2\x10\xd0\x4d\xe2\x10\x00\x0b\xe5\x14\x10\x0b\xe5\x01\x30\xa0\xe3\x08\x30\x0b\xe5\x10\x30\x1b\xe5\x01\x00\x53\xe3\x05\x00\x00\xda\x14\x30\x1b\xe5\x04\x30\x83\xe2\x00\x30\x93\xe5\x03\x00\xa0\xe1\xe9\x01\x00\xeb\x08\x00\x0b\xe5\x08\x30\x1b\xe5\x01\x30\x43\xe2\x08\x00\x53\xe3\x03\xf1\x8f\x90\x1e\x00\x00\xea\x07\x00\x00\xea\x08\x00\x00\xea\x09\x00\x00\xea\x0a\x00\x00\xea\x0b\x00\x00\xea\x0c\x00\x00\xea\x0d\x00\x00\xea\x0e\x00\x00\xea\x0f\x00\x00\xea\x6d\xff\xff\xeb\x18\x00\x00\xea\xcb\xff\xff\xeb\x16\x00\x00\xea\x75\xff\xff\xeb\x14\x00\x00\xea\xfd\xfe\xff\xeb\x12\x00\x00\xea\xbd\xfe\xff\xeb\x10\x00\x00\xea\xd0\xfd\xff\xeb\x0e\x00\x00\xea\x9e\xfd\xff\xeb\x0c\x00\x00\xea\x53\xfd\xff\xeb\x0a\x00\x00\xea\x14\x30\x1b\xe5\x08\x30\x83\xe2\x00\x30\x93\xe5\x03\x00\xa0\xe1\xa1\xfe\xff\xeb\x04\x00\x00\xea\x1c\x30\x9f\xe5\x03\x30\x8f\xe0\x03\x00\xa0\xe1\xff\x13\x00\xeb\x00\x00\xa0\xe1\x00\x30\xa0\xe3\x03\x00\xa0\xe1\x04\xd0\x4b\xe2\x00\x88\xbd\xe8\xfe\xff\xff\xeb"


int main()
{
    ArmDisassembler arm(0);
    const uint8_t arm_code[] = ARM_CODE;
    arm.disass(arm_code , sizeof(arm_code), 0x110c4);
    return 0;
}
#endif