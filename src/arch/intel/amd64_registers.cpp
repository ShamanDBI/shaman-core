#include "registers.hpp"


void AMD64Register::print() {
    uint64_t *cpu_reg = reinterpret_cast<uint64_t *>(m_gp_reg_data);
    m_log->debug("---------------------------------[ REGISTERS START]--------------------------------");
    m_log->debug("RAX {:16x} RBX {:16x} RCX {:16x} RDX {:16x}", 
        cpu_reg[AMD64Register::RAX], cpu_reg[AMD64Register::RBX],
        cpu_reg[AMD64Register::RCX], cpu_reg[AMD64Register::RDX]);
    m_log->debug("RSI {:16x} RDI {:16x} RIP {:16x} RSP {:16x}", 
        cpu_reg[AMD64Register::RSI], cpu_reg[AMD64Register::RDI],
        cpu_reg[AMD64Register::RIP], cpu_reg[AMD64Register::RSP]);
    m_log->debug("R8  {:16x} R9  {:16x} R10 {:16x} R11 {:16x}", 
        cpu_reg[AMD64Register::R8], cpu_reg[AMD64Register::R9],
        cpu_reg[AMD64Register::R10], cpu_reg[AMD64Register::R11]);
    m_log->debug("R12 {:16x} R13 {:16x} R14 {:16x} R15 {:16x}", 
        cpu_reg[AMD64Register::R12], cpu_reg[AMD64Register::R13],
        cpu_reg[AMD64Register::R14], cpu_reg[AMD64Register::R15]);
    m_log->debug("EFLAGS  {:16x}", cpu_reg[AMD64Register::EFLAGS]);
    m_log->debug("FS  {:16x} GS  {:16x} ES  {:16x} DS  {:16x}", 
        cpu_reg[AMD64Register::FS], cpu_reg[AMD64Register::GS],
        cpu_reg[AMD64Register::ES], cpu_reg[AMD64Register::DS]);
    m_log->debug("---------------------------------[ REGISTERS STOP  ]--------------------------------");
}
