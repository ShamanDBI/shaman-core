#include "registers.hpp"


#define ARCH_GP_REG_CNT 27

enum INTEL_X64_REGS {
    R15 = 0,
    R14,
    R13,
    R12,
    RBP,
    RBX,
    R11,
    R10,
    R9,
    R8,
    RAX,
    RCX,
    RDX,
    RSI,
    RDI,
    ORIG_RAX,
    RIP,
    CS,
    EFLAGS,
    RSP,
    SS,
    FS_BASE,
    GS_BASE,
    DS,
    ES,
    FS,
    GS,
};

Registers::~Registers() {
    free(reinterpret_cast<uint64_t *>(gp_reg));
}

Registers::Registers(pid_t tracee_pid) : m_pid(tracee_pid) {
    gp_reg_size = sizeof(uint64_t) * ARCH_GP_REG_CNT;
    gp_reg = reinterpret_cast<uintptr_t>(malloc(gp_reg_size));
}

uint64_t Registers::getPC() {
    // PC register points to the next instruction
    return reinterpret_cast<uint64_t *>(gp_reg)[INTEL_X64_REGS::RIP];
}

uint64_t Registers::setPC(uint64_t reg_val) {
    return reinterpret_cast<uint64_t *>(gp_reg)[INTEL_X64_REGS::RIP] = reg_val;
}

uint64_t Registers::getSP() {
    return reinterpret_cast<uint64_t *>(gp_reg)[INTEL_X64_REGS::RSP];
}

uint64_t Registers::getRegIdx(uint8_t reg_idx) {
    return reinterpret_cast<uint64_t *>(gp_reg)[reg_idx];
}

void Registers::print() {
    uint64_t *cpu_reg = reinterpret_cast<uint64_t *>(gp_reg);
    m_log->debug("---------------------------------[ REGISTERS START]--------------------------------");
    m_log->debug("RAX {:16x} RBX {:16x} RCX {:16x} RDX {:16x}", 
        cpu_reg[INTEL_X64_REGS::RAX], cpu_reg[INTEL_X64_REGS::RBX],
        cpu_reg[INTEL_X64_REGS::RCX], cpu_reg[INTEL_X64_REGS::RDX]);
    m_log->debug("RSI {:16x} RDI {:16x} RIP {:16x} RSP {:16x}", 
        cpu_reg[INTEL_X64_REGS::RSI], cpu_reg[INTEL_X64_REGS::RDI],
        cpu_reg[INTEL_X64_REGS::RIP], cpu_reg[INTEL_X64_REGS::RSP]);
    m_log->debug("R8  {:16x} R9  {:16x} R10 {:16x} R11 {:16x}", 
        cpu_reg[INTEL_X64_REGS::R8], cpu_reg[INTEL_X64_REGS::R9],
        cpu_reg[INTEL_X64_REGS::R10], cpu_reg[INTEL_X64_REGS::R11]);
    m_log->debug("R12 {:16x} R13 {:16x} R14 {:16x} R15 {:16x}", 
        cpu_reg[INTEL_X64_REGS::R12], cpu_reg[INTEL_X64_REGS::R13],
        cpu_reg[INTEL_X64_REGS::R14], cpu_reg[INTEL_X64_REGS::R15]);
    m_log->debug("EFLAGS  {:16x}", cpu_reg[INTEL_X64_REGS::EFLAGS]);
    m_log->debug("FS  {:16x} GS  {:16x} ES  {:16x} DS  {:16x}", 
        cpu_reg[INTEL_X64_REGS::FS], cpu_reg[INTEL_X64_REGS::GS],
        cpu_reg[INTEL_X64_REGS::ES], cpu_reg[INTEL_X64_REGS::DS]);
    m_log->debug("---------------------------------[ REGISTERS STOP  ]--------------------------------");
}
