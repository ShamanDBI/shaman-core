// #include "memory.hpp"
#include <cstdint>
#include <cstdlib>
#include <sys/ptrace.h>
#include <cstring>
#include <sys/types.h>
#include "stdio.h"
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>
#include <spdlog/spdlog.h>


using namespace std;

class Addr {

private:

public:
    uint8_t* addr;
    uint64_t r_addr;
    size_t size;
    
    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size): size(_size), r_addr(_r_addr) {
        addr = (uint8_t *) malloc(_size);
        printf("mem alloc , %lu\n", size);
    }
    void clean() {
        // set the data to zero
        memset(addr, 0, size);
    }
    // Addr(uint64_t _addr, size_t _size): size(_size), 
    //     addrType(REMOTE), addr((uint8_t *)_addr) {}

    ~Addr() {
        // if(addrType == LOCAL)
            free(addr);
    }
};


class RemoteMemory {

    pid_t m_pid;

public:

    RemoteMemory(pid_t tracee_pid) : m_pid(tracee_pid) {}
    
    struct user_regs_struct* getGPRegisters() {
        struct iovec io;
        struct user_regs_struct* regs = (struct user_regs_struct*)malloc(sizeof(struct user_regs_struct));
        io.iov_base = regs;
        io.iov_len = sizeof(struct user_regs_struct);

        int ret = ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);

        if (ret < 0) {
            spdlog::error("Unable to get tracee [pid : {}] register, Err code: ", m_pid, ret);
        }
        return regs;
    }

    int setGPRegisters(struct user_regs_struct* regs) {
        struct iovec io;
        io.iov_base = regs;
        io.iov_len = sizeof(struct user_regs_struct);
        int ret = ptrace(PTRACE_SETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io);
        if (ret < 0) {
            spdlog::error("Unable to get tracee [pid : {}] register, Err code: ", m_pid, ret);
        }
        return ret;
    }
    
    int read(Addr *dest, size_t readSize) {
        
        unsigned int bytes_read = 0;
        long * read_addr = (long *) dest->r_addr;
        long * copy_addr = (long *) dest->addr;
        unsigned long ret;
        memset(dest->addr, '\0', readSize);

        do {
            ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
            // printf("RD : %p\n", ret);
            *(copy_addr++) = ret;
            bytes_read += sizeof(long);
        } while(ret && bytes_read < (readSize - sizeof(long)));
        
        return bytes_read;

    }
    
    int write(Addr *data, size_t writeSize) {

        unsigned int bytes_write = 0;
        long * write_addr = (long *) data->r_addr;
        long * copy_addr = (long *) data->addr;
        long ret;
        
        do {
            ret = ptrace(PTRACE_POKEDATA, m_pid, (write_addr++), *(copy_addr++));
            // printf("WD : %lu \t", ret);
            bytes_write += sizeof(long);
            // printf("%lu %lu %d\n", bytes_write , (writeSize - sizeof(long)), ret > -1);
        } while((ret > -1 )&& bytes_write < (writeSize - sizeof(long)));
        
        return bytes_write;
    }

    int read_cstring() {
        return 0;
    }
};


#define BREAKPOINT_INST 0xcc;
#define NOP_INST 0x90;
#define BREAKPOINT_SIZE sizeof(uint64_t)
#include "spdlog/fmt/bin_to_hex.h"

class Breakpoint {
    bool m_enabled;
    uintptr_t m_addr;
    pid_t m_pid;
    string &label;
    // breakpoint data is written to the memory
    Addr *m_backupData;
    RemoteMemory *m_remoteMemory;
    uint32_t m_count = 0;
public:

    ~Breakpoint() { 
        delete m_backupData;
        delete m_remoteMemory;
    }

    Breakpoint(uintptr_t bk_addr, pid_t tracee_pid, string& _label): m_addr(bk_addr),
        m_enabled(true), m_pid(tracee_pid), label(_label),
        m_backupData(new Addr(bk_addr, BREAKPOINT_SIZE)),
        m_remoteMemory(new RemoteMemory(tracee_pid)) {}

    void enable() {
        uint8_t backup;
        m_remoteMemory->read(m_backupData, BREAKPOINT_SIZE);
        backup = m_backupData->addr[0];
        m_backupData->addr[0] = BREAKPOINT_INST;
        m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
        m_backupData->addr[0] = backup;
        m_enabled = true;
    }
    
    void printDebug() {
        spdlog::warn("BRK [0x{:x}] [{}] pid {} count {} ", m_addr, label, m_pid, m_count);
    }

    void handle() {
        m_count++;
        printDebug();
    }

    void disable() {
        m_remoteMemory->write(m_backupData, BREAKPOINT_SIZE);
        m_backupData->clean();
        m_enabled = false;
    }

    bool isEnabled() {
        return m_enabled;
    }

};