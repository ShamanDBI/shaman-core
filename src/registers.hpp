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
} ;

template <class T> class Registers {

    pid_t m_pid;
public:
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
    T* gp_reg;
    uint8_t m_gp_reg_count;
    uint16_t gp_reg_size;
    uint8_t program_register_idx = 0;
    uint8_t stack_pointer_register_idx = 0;

    ~Registers();
    Registers(pid_t tracee_pid, uint8_t reg_cnt);

    virtual T getProgramCounter();
    virtual void setProgramCounter(T reg_val);
    virtual T getStackPointer();
    virtual T getRegIdx(uint8_t reg_idx);
    virtual T setRegIdx(uint8_t reg_idx, T value);

    virtual void print() = 0;

    virtual int getGPRegisters() {
        struct iovec io;
        
        io.iov_base = reinterpret_cast<void *>(gp_reg);
        io.iov_len = gp_reg_size;

        int pt_ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (pt_ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, pt_ret);
        }

        return pt_ret;
    };

    virtual int setGPRegisters() {
        struct iovec io;

        io.iov_base = reinterpret_cast<void *>(gp_reg);
        io.iov_len = gp_reg_size;

        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);

        if (ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, ret);
        }
        return ret;
    };

};

#define ARCH_X86_GP_REG_CNT 17

class X86Register: Registers<uint32_t> {

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
        : Registers<uint32_t>(tracee_pid, ARCH_X86_GP_REG_CNT) {
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::EIP);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::ESP);
    }

    void print();
};


#define ARCH_AMD64_GP_REG_CNT 27

class AMD64Register: Registers<uint64_t> {

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
        : Registers<uint64_t>(tracee_pid, ARCH_AMD64_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::RIP);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::RSP);
    }

    void print();

};

#define ARCH_ARM_GP_REG_CNT 18

class ARMRegister: Registers<uint32_t> {

public:
    enum REGISTER_IDX : uint8_t {
        R0 = 0,
        PS,
        SP
    };

    ARMRegister(pid_t tracee_pid)
        : Registers<uint32_t>(tracee_pid, ARCH_ARM_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PS);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
    }
};

#define ARCH_ARM64_GP_REG_CNT 32

class ARM64Register: Registers<uint64_t> {

public:
    enum REGISTER_IDX : uint8_t {
        X0 = 0,
        PS,
        SP
    };

    ARM64Register(pid_t tracee_pid)
        : Registers<uint64_t>(tracee_pid, ARCH_ARM_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PS);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
    }
};

#endif