#ifndef H_REGISTER_H
#define H_REGISTER_H

#include "spdlog/spdlog.h"
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>

struct RegisterAliases {
  const char *const name;
  int regnum;
};

/**
 * @brief Abstraction for represent Register of the Tracee
*/
class Registers {

protected:

    pid_t m_pid;
    uint8_t m_gp_reg_count;
    uint16_t m_gp_reg_size;
    std::uintptr_t m_gp_reg_data;
    uint8_t program_register_idx = 0;
    uint8_t stack_pointer_register_idx = 0;
    uint8_t frame_base_pointer_register_idx = 0;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main");

public:

    Registers(pid_t tracee_pid, uint8_t _gp_reg_count, uint16_t _gp_reg_size)
        : m_pid(tracee_pid), m_gp_reg_count(_gp_reg_count),
          m_gp_reg_size(_gp_reg_size)
    {
        m_gp_reg_data = reinterpret_cast<uintptr_t>(malloc(m_gp_reg_size));
    }
    
    // Destructor
    ~Registers() {
        free(reinterpret_cast<void *>(m_gp_reg_data));
    }

    void setPid(pid_t tracee_pid) { 
        m_pid = tracee_pid;
    }

    /// @brief read the General Purpose register of the Tracee Process
    /// @return return the ptrace error value
    virtual int fetch() {
        struct iovec io;
        
        io.iov_base = reinterpret_cast<void *>(m_gp_reg_data);
        io.iov_len = m_gp_reg_size;

        int pt_ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (pt_ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, pt_ret);
        }

        return pt_ret;
    }

    /// @brief Upate the general purpose register value to the Tracee Process
    /// @return 
    virtual int update() {
        struct iovec io;

        io.iov_base = reinterpret_cast<void *>(m_gp_reg_data);
        io.iov_len = m_gp_reg_size;

        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);

        if (ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, ret);
        }
        return ret;
    }

    /// @brief Creates a copy for General Purpose registers
    /// freeing the returned copy is the responsibility of the Caller
    /// @return return the copy of register.
    std::uintptr_t getRegisterCopy() {
        void* gp_reg_copy = malloc(m_gp_reg_size);
        memcpy(gp_reg_copy, reinterpret_cast<void*>(m_gp_reg_data), m_gp_reg_size);
        return reinterpret_cast<std::uintptr_t>(gp_reg_copy);
    }

    /// @brief Restore the copy of the register
    /// You can obtain the copy of the GP Register using `getRegisterCopy` function
    /// @param register_copy 
    void restoreRegisterCopy(std::uintptr_t register_copy) {
        memcpy(reinterpret_cast<void *>(m_gp_reg_data), reinterpret_cast<void *>(register_copy), m_gp_reg_size);
    }

};


template <class T> class IRegisters : public Registers {

public:

    IRegisters(pid_t tracee_pid, uint8_t _gp_reg_cnt) 
     : Registers::Registers(tracee_pid, _gp_reg_cnt, sizeof(T) * _gp_reg_cnt) {};
    
    virtual T getRegIdx(uint8_t reg_idx) {
        return reinterpret_cast<T *>(m_gp_reg_data)[reg_idx];
    }

    virtual void setRegIdx(uint8_t reg_idx, T value) {
        reinterpret_cast<T *>(m_gp_reg_data)[reg_idx] = value;
    }

    virtual T getProgramCounter() {
        // PC register points to the next instruction
        return getRegIdx(program_register_idx);
    }

    void setProgramCounter(T reg_val) {
        reinterpret_cast<T *>(m_gp_reg_data)[program_register_idx] = reg_val;
    }

    virtual T getStackPointer() {
        return getRegIdx(stack_pointer_register_idx);
    }

    virtual T getBreakpointAddr() {
        return getProgramCounter() - 1;
    }

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

    uint32_t getBreakpointAddr() {
        return getProgramCounter() - 1;
    }

    void print();
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

    uint64_t getBreakpointAddr() {
        return getProgramCounter() - 1;
    }

    void print();

};

#define ARCH_ARM_GP_REG_CNT 18
#define CPSR_THUMB 0x20
#include <capstone/capstone.h>

class ARM32Register: public IRegisters<uint32_t> {

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
        FP, // Frame Pointer
        IP, // 
        SP,
        LR,
        PC,
        CPSR,
        ORIG_R0
    };
    int* arm_cap_reg_map;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("debugger");

    ARM32Register(pid_t tracee_pid)
        : IRegisters<uint32_t>(tracee_pid, ARCH_ARM_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PC);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::FP);
        arm_cap_reg_map = new int[ARM_REG_ENDING];
        arm_cap_reg_map[ARM_REG_R0] = ARM32Register::R0;
        arm_cap_reg_map[ARM_REG_R1] = ARM32Register::R1;
        arm_cap_reg_map[ARM_REG_R2] = ARM32Register::R2;
        arm_cap_reg_map[ARM_REG_R3] = ARM32Register::R3;
        arm_cap_reg_map[ARM_REG_R4] = ARM32Register::R4;
        arm_cap_reg_map[ARM_REG_R5] = ARM32Register::R5;
        arm_cap_reg_map[ARM_REG_R6] = ARM32Register::R6;
        arm_cap_reg_map[ARM_REG_R7] = ARM32Register::R7;
        arm_cap_reg_map[ARM_REG_R8] = ARM32Register::R8;
        arm_cap_reg_map[ARM_REG_R9] = ARM32Register::R9;
        arm_cap_reg_map[ARM_REG_R10] = ARM32Register::R10;
        arm_cap_reg_map[ARM_REG_FP] = ARM32Register::FP;
        arm_cap_reg_map[ARM_REG_IP] = ARM32Register::IP;
        arm_cap_reg_map[ARM_REG_SP] = ARM32Register::SP;
        arm_cap_reg_map[ARM_REG_LR] = ARM32Register::LR;
        arm_cap_reg_map[ARM_REG_PC] = ARM32Register::PC;
    }

    uint32_t getBreakpointAddr() {
        return getProgramCounter();
    }

    uint32_t getCapRegValue(int reg_id) {
        // m_log->debug("CAP Reg ID : {} {}", reg_id, arm_cap_reg_map[reg_id]);
        return getRegIdx(arm_cap_reg_map[reg_id]);
    }

    bool isThumbMode() {
        return getRegIdx(REGISTER_IDX::CPSR) & CPSR_THUMB;
    }

    void print() {
        m_log->debug("--------------------[ ARM REGISTER ]--------------------");

        for(int i=0; i < ARCH_ARM_GP_REG_CNT; i++) {
            switch (i) {
            case PC:
                m_log->debug("\tPC   {:#04x}", getRegIdx(i));
                break;
            case SP:
                m_log->debug("\tSP   {:#04x}", getRegIdx(i));
                break;
            case LR:
                m_log->debug("\tLR   {:#04x}", getRegIdx(i));
                break;
            case FP:
                m_log->debug("\tFP   {:#04x}", getRegIdx(i));
                break;
            case IP:
                m_log->debug("\tIP   {:#04x}", getRegIdx(i));
                break;
            case CPSR:
                m_log->debug("\tCPSR {:#04x}", getRegIdx(i));
                break;
            default:
                m_log->debug("\tR{:<3} {:#04x}",i, getRegIdx(i));
                break;
            }
        }
        m_log->debug("--------------------[ ARM END REGISTER ]-----------------");
    };
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
        PC,
        LR,
        CPSR
    };

    ARM64Register(pid_t tracee_pid)
        : IRegisters<uint64_t>(tracee_pid, ARCH_ARM64_GP_REG_CNT) {
        
        program_register_idx = static_cast<uint8_t>(REGISTER_IDX::PC);
        stack_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::SP);
        frame_base_pointer_register_idx = static_cast<uint8_t>(REGISTER_IDX::FP);
    }

    uint64_t getBreakpointAddr() {
        return getProgramCounter();
    }

    void print() {
        for(int i=0; i < ARCH_ARM64_GP_REG_CNT; i++) {
            m_log->debug("X{:<3} {:#04x}",i, getRegIdx(i));
        }
    };
};

#endif