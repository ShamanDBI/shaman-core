#ifndef H_REGISTER_H
#define H_REGISTER_H

#include <cstdint>
#include <spdlog/spdlog.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>


struct RegisterAliases {
  const char *const name;
  int regnum;
};

#define REG_OFFSET_NAME(r, ARCH) \
	{.name = #r, .offset = offsetof(struct pt_regs, ##ARCH_##r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}


class Registers {

protected:

    pid_t m_pid;
    uint8_t m_gp_reg_count;
    uint16_t m_gp_reg_size;
    std::uintptr_t m_gp_reg_data;
    uint8_t program_register_idx = 0;
    uint8_t stack_pointer_register_idx = 0;
    uint8_t frame_base_pointer_register_idx = 0;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

public:

    Registers(pid_t tracee_pid, uint8_t _gp_reg_count, uint16_t _gp_reg_size)
        : m_pid(tracee_pid), m_gp_reg_count(_gp_reg_count),
          m_gp_reg_size(_gp_reg_size)
    {
        m_gp_reg_data = reinterpret_cast<uintptr_t>(malloc(m_gp_reg_size));
    };
    
    ~Registers() {
        free(reinterpret_cast<void *>(m_gp_reg_data));
    };

    void setPid(pid_t tracee_pid) { 
        m_pid = tracee_pid;
    };

    virtual int fetch() {
        struct iovec io;
        
        io.iov_base = reinterpret_cast<void *>(m_gp_reg_data);
        io.iov_len = m_gp_reg_size;

        int pt_ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (pt_ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, pt_ret);
        }

        return pt_ret;
    };

    virtual int update() {
        struct iovec io;

        io.iov_base = reinterpret_cast<void *>(m_gp_reg_data);
        io.iov_len = m_gp_reg_size;

        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);

        if (ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, ret);
        }
        return ret;
    };
};


template <class T> class IRegisters : public Registers {

public:

    IRegisters(pid_t tracee_pid, uint8_t _gp_reg_cnt) 
    : Registers::Registers(tracee_pid, _gp_reg_cnt, sizeof(T) * _gp_reg_cnt) {};
    
    virtual T getProgramCounter();
    virtual void setProgramCounter(T reg_val);
    virtual T getStackPointer();
    virtual T getRegIdx(uint8_t reg_idx);
    virtual T setRegIdx(uint8_t reg_idx, T value);

    virtual void print() = 0;

};

#define ARCH_X86_GP_REG_CNT 17

class X86Register: public IRegisters<uint32_t> {

public:
    enum REGISTER_IDX : uint8_t {
        EBX = 0,
        ECX,
        EDX,
        ESI,
        EDI,
        EBP,
        EAX,
        DS,
        ES,
        FS,
        GS,
        ORIG_EAX,
        EIP,
        CS,
        EFLAGS,
        ESP,
        SS,
    };

    X86Register(pid_t tracee_pid)
        : IRegisters<uint32_t>(tracee_pid, ARCH_X86_GP_REG_CNT) {
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::EIP);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::ESP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::EBP);
    }

    void print() {};
};


#define ARCH_AMD64_GP_REG_CNT 27

class AMD64Register: public IRegisters<uint64_t> {

public:
    enum REGISTER_IDX : uint8_t {
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

    AMD64Register(pid_t tracee_pid)
        : IRegisters<uint64_t>(tracee_pid, ARCH_AMD64_GP_REG_CNT) {
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::RIP);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::RSP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::RBP);
    }

    void print() {};

};

#define ARCH_ARM_GP_REG_CNT 18

class ARMRegister: public IRegisters<uint32_t> {

public:
    enum REGISTER_IDX : uint8_t {
        R0 = 0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        FP,
        IP,
        SP,
        LR,
        PC,
        CPSR,
        ORIG_R0
    };

    ARMRegister(pid_t tracee_pid)
        : IRegisters<uint32_t>(tracee_pid, ARCH_ARM_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PC);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::FP);
    }
    void print() {};
};

#define ARCH_ARM64_GP_REG_CNT 35

class ARM64Register: public IRegisters<uint64_t> {

public:
    enum REGISTER_IDX : uint8_t {
        X0 = 0,
        X1,
        X2,
        X3,
        X4,
        X5,
        X6,
        X7,
        X8,
        X9,
        X10,
        X11,
        X12,
        X13,
        X14,
        X15,
        X16,
        X17,
        X18,
        X19,
        X20,
        X21,
        X22,
        X23,
        X24,
        X25,
        X26,
        X27,
        X28,
        FP,
        IP,
        SP,
        LR,
        PC,
        CPSR
    };

    ARM64Register(pid_t tracee_pid)
        : IRegisters<uint64_t>(tracee_pid, ARCH_ARM_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PC);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::FP);
    }
    void print() {};
};

#endif