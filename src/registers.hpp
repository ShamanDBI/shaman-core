#ifndef H_REGISTER_H
#define H_REGISTER_H

#include <cstdint>
#include <spdlog/spdlog.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>

#define ARCH_GP_REG_CNT 27


class Registers {

    pid_t m_pid;
    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
public:
    uintptr_t gp_reg;
    uintptr_t gp_reg_size;

    ~Registers();
    Registers(pid_t tracee_pid);

    uint64_t getPC();
    uint64_t setPC(uint64_t reg_val);
    uint64_t getSP();
    uint64_t getRegIdx(uint8_t reg_idx);

    void print();

    int getGPRegisters() {
        struct iovec io;
        
        io.iov_base = reinterpret_cast<void *>(gp_reg);
        io.iov_len = gp_reg_size;

        int pt_ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (pt_ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, pt_ret);
        }

        return pt_ret;
    }

    int setGPRegisters() {
        struct iovec io;

        io.iov_base = reinterpret_cast<void *>(gp_reg);
        io.iov_len = gp_reg_size;

        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);

        if (ret < 0) {
            m_log->error("Unable to get tracee [pid : {}] register, Err code: {}", m_pid, ret);
        }
        return ret;
    }

};

#endif