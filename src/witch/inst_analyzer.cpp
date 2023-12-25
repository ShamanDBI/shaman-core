#include "inst_analyzer.hpp"
#include "debug_opts.hpp"
#include "debugger.hpp"


bool ARMInstAnalyzer::isBranch(const cs_insn *inst) const noexcept {
    if (inst->detail == NULL) return false;

    cs_detail *detail = inst->detail;
    // assuming that each instruction should belong to at least one group
    if (detail->groups[detail->groups_count - 1] == ARM_GRP_JUMP)
        return true;
    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) {
                printf("PC reg at idx %d\n", i + 1);
                return true;
            }
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        return true;
    }
    return false;
}

bool ARMInstAnalyzer::isConditional(cs_insn *inst) const {
    return inst->detail->arm.cc != ARM_CC_AL;
}

bool ARMInstAnalyzer::getBranchDest(cs_insn* inst, BranchData& branch_info, DebugOpts& debug_opts) {
    cs_detail *detail;
    detail = inst->detail;
    int n = 0;
    bool _found_dest = false;
    
    ARM32Register& arm_reg = reinterpret_cast<ARM32Register&>(debug_opts.m_register);

    if (detail == NULL) {
        m_log->error("Details not found!\n");
        return false;
    }

    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) {
                // read the stack memory and figure out the branch destination
                // printf("PC idx %d = [SP - %d]\n", i + 1, i*4);
                Addr* sp_addr = debug_opts.m_memory.readPointerObj(arm_reg.getStackPointer() + 4, 4);
                branch_info.m_direct_branch = true;
                branch_info.m_target = sp_addr->read_u32();
                _found_dest = true;
            }
        }
    }



    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        _found_dest = true;

        // we have to emulate the instruction to calculate the destination branch
        SPDLOG_LOGGER_TRACE(m_log, "Emulation Zone");
        arm_reg.print();

        branch_info.m_is_computed = true;
        branch_info.m_direct_branch = false;

        uint32_t val_1 = 0, val_2 = 0;
        
        // Get the first operand, this has to be only register value
        if (detail->arm.operands[1].type == ARM_OP_REG) {
            val_1 = arm_reg.getCapRegValue(detail->arm.operands[1].reg);
        } else {
            m_log->error("1st operand is not register");
        }

        
        // Extraction the second operand
        cs_arm_op *sec_op = &(detail->arm.operands[2]);
        switch(sec_op->type) {
            case ARM_OP_REG:
                val_2 = arm_reg.getCapRegValue(sec_op->reg);
                SPDLOG_LOGGER_DEBUG(m_log, "sec operands[{}].type: REG ID = {}", n, sec_op->reg);
                break;
            case ARM_OP_IMM:
                val_2 = sec_op->imm;
                SPDLOG_LOGGER_DEBUG(m_log, "sec operands[{}].type: IMM = 0x{:x}", n, sec_op->imm);
                break;
            case ARM_OP_MEM:
                m_log->error("sec operands[{}].type: MEM", n);
                if (sec_op->mem.base != ARM_REG_INVALID)
                    m_log->error("\tsec operands[{}].mem.base: REG ID = {}", n, sec_op->mem.base);
                if (sec_op->mem.index != ARM_REG_INVALID)
                    m_log->error("\tsec operands[{}].mem.index: REG ID = {}", n, sec_op->mem.index);
                if (sec_op->mem.disp != 0)
                    m_log->error("\tsec operands[{}].mem.disp: 0x{:x}", n, sec_op->mem.disp);
                break;
            case ARM_OP_CIMM:
                m_log->error("sec operands[{}].type: C-IMM = {}", n, sec_op->imm);
                break;
        }

        if (sec_op->shift.type != ARM_SFT_INVALID && sec_op->shift.value) {
            m_log->debug("\t\t\tShift: type = {}, value = {}", sec_op->shift.type, sec_op->shift.value);
            
            switch (sec_op->shift.type)
            {
            case ARM_SFT_LSL:
                val_2 = val_2 << sec_op->shift.value;
                break;
            case ARM_SFT_LSR:
                val_2 = val_2 >> sec_op->shift.value;
            default:
                m_log->error("Please handle this type of Shift computation! Shift ID : {}", sec_op->shift.type);
                break;
            }

        }
        SPDLOG_LOGGER_DEBUG(m_log, "Opt 1 : 0x{:x} Opt 2 : 0x{:x}", val_1, val_2);
        // m_log->debug("Val 1 : 0x{:x} Val 2 : 0x{:x}", val_1, val_2);
        switch (inst->id) {
        case ARM_INS_ADD:
            val_1 = val_1 + val_2;
            break;
        case ARM_INS_SUB:
            val_1 = val_1 - val_2;
            break;
        default:
            m_log->error("Please handle this type of JUMP computation! Inst ID : {}", inst->id);
            return false;
            break;
        }
        SPDLOG_LOGGER_DEBUG(m_log, "Res : 0x{:x}", val_1, val_2);

        // Adjust the target to pointer two instruction ahead
        branch_info.m_target = val_1 + (4*2);
    }

    if (inst->id == ARM_INS_CBZ || inst->id == ARM_INS_CBNZ) {
        if(detail->arm.op_count == 2 && detail->arm.operands[1].type == ARM_OP_IMM) {
            branch_info.m_direct_branch = true;
            branch_info.m_target = detail->arm.operands[1].imm;
            _found_dest = true;
        }
        SPDLOG_LOGGER_DEBUG(m_log, "Error while analyzing CBZ Instruction\n");
    }

    if (detail->groups_count > 0) {
        for (n = 0; n < detail->groups_count; n++) {
            switch(detail->groups[n]) {
                case CS_GRP_CALL:
                    branch_info.m_is_call = true;
                case CS_GRP_JUMP:
                case CS_GRP_BRANCH_RELATIVE:
                    if(detail->arm.op_count == 1 && detail->arm.operands[0].type == ARM_OP_IMM) {
                        branch_info.m_direct_branch = true;
                        branch_info.m_target = detail->arm.operands[0].imm;
                        _found_dest = true;
                    }
                break;
            }
        }
    }

    
    if(isConditional(inst)) {
       // this mean we need a fall-though breakpoint
        branch_info.m_conditional_branch = true;
        branch_info.m_fall_target = inst->address + inst->size;
    }

    if(!_found_dest) {
        branch_info.m_target = inst->address + inst->size;
    }

    return true;
}

void ARMInstAnalyzer::prettyPrintCapstoneInst(const csh &handle, cs_insn *inst, bool details_enabled) {

    cs_detail *detail;
    int n;
    m_log->debug("0x{:x}  :\t{}\t\t{}", inst->address, inst->mnemonic, inst->op_str);

    if (!details_enabled) {
        return;
    }
    // print implicit registers used by this instruction
    detail = inst->detail;
    if (detail == NULL) {
        m_log->error("Details not found!\n");
        return;
    }

    for (n = 0; n < detail->arm.op_count; n++) {
        cs_arm_op *op = &(detail->arm.operands[n]);
        switch(op->type) {
            case ARM_OP_REG:
                m_log->debug("\t\toperands[{}].type: REG = {}", n, cs_reg_name(handle, op->reg));
                break;
            case ARM_OP_IMM:
                m_log->debug("\t\toperands[{}].type: IMM = 0x{:x}", n, op->imm);
                break;
            case ARM_OP_FP:
                m_log->debug("\t\toperands[{}].type: FP = {}", n, op->fp);
                break;
            case ARM_OP_MEM:
                m_log->debug("\t\toperands[{}].type: MEM", n);
                if (op->mem.base != ARM_REG_INVALID)
                    m_log->debug("\t\t\toperands[{}].mem.base: REG = {}", n, cs_reg_name(handle, op->mem.base));
                if (op->mem.index != ARM_REG_INVALID)
                    m_log->debug("\t\t\toperands[{}].mem.index: REG = {}", n, cs_reg_name(handle, op->mem.index));
                if (op->mem.disp != 0)
                    m_log->debug("\t\t\toperands[{}].mem.disp: 0x{:x}", n, op->mem.disp);
                break;
            case ARM_OP_CIMM:
                m_log->debug("\t\toperands[{}].type: C-IMM = {}", n, op->imm);
                break;
        }

        if (op->shift.type != ARM_SFT_INVALID && op->shift.value)
            m_log->debug("\t\t\tShift: type = {}, value = {}", op->shift.type, op->shift.value);
    }

    if (detail->regs_read_count > 0) {
        m_log->debug("\tRegisters READ: ");
        for (n = 0; n < detail->regs_read_count; n++) {
            m_log->debug("\t\t{} ", cs_reg_name(handle, detail->regs_read[n]));
        }
    }

    // Print Implicit registers modified by this instruction
    if (detail->regs_write_count > 0) {
        m_log->debug("\tRegisters WRITE: ");
        for (n = 0; n < detail->regs_write_count; n++) {
            m_log->debug("\t\t{}", cs_reg_name(handle, detail->regs_write[n]));
        }
    }

    if (detail->arm.cc != ARM_CC_INVALID) {
        std::string cc_str = conditionCodeToString(detail->arm.cc);
        m_log->debug("\tCode condition: {}", cc_str.c_str());
    }

    if (detail->arm.update_flags)
        m_log->debug("\tUpdate-flags: True");

    if (detail->arm.writeback)
        m_log->debug("\tWrite-back: True");

    // print the groups this instruction belong to
    if (detail->groups_count > 0) {
        m_log->debug("\tGROUPS: ");
        for (n = 0; n < detail->groups_count; n++) {
            m_log->debug("\t\t{} ", cs_group_name(handle, detail->groups[n]));
        }
    }
}

const std::string ARMInstAnalyzer::conditionCodeToString(const arm_cc &condition) const {
    switch (condition) {
        case ARM_CC_INVALID:
            return "Invalid";
        case ARM_CC_EQ:
            return "Equal";
        case ARM_CC_NE:
            return "Not equal";
        case ARM_CC_HS:
            return "Carry set";
        case ARM_CC_LO:
            return "Carry clear";
        case ARM_CC_MI:
            return "Minus";
        case ARM_CC_PL:
            return "Plus";
        case ARM_CC_VS:
            return "Overflow";
        case ARM_CC_VC:
            return "No overflow";
        case ARM_CC_HI:
            return "Unsigned higher";
        case ARM_CC_LS:
            return "Unsigned Lower OR Same";
        case ARM_CC_GE:
            return "Greater than OR equal";
        case ARM_CC_LT:
            return "Less than";
        case ARM_CC_GT:
            return "Greater than";
        case ARM_CC_LE:
            return "Less than OR equal";
        case ARM_CC_AL:
            return "Always";
        default:
            return "Unknown";
    }
}

bool ARMInstAnalyzer::isDirectBranch(cs_insn *inst) const {
    if (inst->id == ARM_INS_CBZ || inst->id == ARM_INS_CBNZ) {
        return true;
    }
    if (inst->detail->arm.op_count == 1
        && inst->detail->arm.operands[0].type == ARM_OP_IMM) {
        return true;
    }
    return false;
}


