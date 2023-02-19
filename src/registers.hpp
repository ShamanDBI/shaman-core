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

public:
    uintptr_t gp_reg;
    uintptr_t gp_reg_size;

    ~Registers();
    Registers(pid_t tracee_pid);

    uint64_t getPC();
    uint64_t setPC(uint64_t reg_val);
    uint64_t getSP();

    int getGPRegisters();
    int setGPRegisters();
    void print();

};

#endif