#include "registers.hpp"


void X86Register::print() {
    uint32_t *cpu_reg = reinterpret_cast<uint32_t *>(m_gp_reg_data);
    m_log->debug("---------------------------------[ REGISTERS START]--------------------------------");
    m_log->debug("RAX {:16x} RBX {:16x} RCX {:16x} RDX {:16x}", 
        cpu_reg[X86Register::EAX], cpu_reg[X86Register::EBX],
        cpu_reg[X86Register::ECX], cpu_reg[X86Register::EDX]);
    m_log->debug("RSI {:16x} RDI {:16x} RIP {:16x} RSP {:16x}", 
        cpu_reg[X86Register::ESI], cpu_reg[X86Register::EDI],
        cpu_reg[X86Register::EIP], cpu_reg[X86Register::ESP]);
    m_log->debug("EFLAGS  {:16x}", cpu_reg[X86Register::EFLAGS]);
    m_log->debug("FS  {:16x} GS  {:16x} ES  {:16x} DS  {:16x}", 
        cpu_reg[X86Register::FS], cpu_reg[X86Register::GS],
        cpu_reg[X86Register::ES], cpu_reg[X86Register::DS]);
    m_log->debug("---------------------------------[ REGISTERS STOP  ]--------------------------------");
}
