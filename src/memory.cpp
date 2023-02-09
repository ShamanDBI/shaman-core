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

class Addr {

private:

public:
    uint8_t* addr;
    uint64_t r_addr;
    size_t size;
    
    Addr(uint64_t _r_addr, size_t _size): size(_size), r_addr(_r_addr) {
        addr = (uint8_t *) malloc(_size);
        printf("mem alloc , %lu\n", size);
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
    
    struct user_regs_struct* readRegs() {
        struct iovec io;
        struct user_regs_struct* regs = (struct user_regs_struct*)malloc(sizeof(struct user_regs_struct));
        io.iov_base = regs;
        io.iov_len = sizeof(struct user_regs_struct);

        if (ptrace(PTRACE_GETREGSET, m_pid, (void*)NT_PRSTATUS, (void*)&io) == -1) {
            printf("ERROR : enable to get tracee register\n");
        }
        return regs;
    }
    
    int read(Addr *dest, size_t readSize) {
        unsigned int bytes_read = 0;
        long * read_addr = (long *) dest->r_addr;
        long * copy_addr = (long *) dest->addr;
        unsigned long ret;
        memset(dest->addr, '\0', readSize);
        do {
            ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
            printf("RD : %p\n", ret);
            *(copy_addr++) = ret;
            bytes_read += sizeof(long);
        } while(ret && bytes_read < (readSize - sizeof(long)));
        return bytes_read;

    }
    
    int write(Addr localAddr, Addr remoteAddr, size_t writeSize) {
        // ptrace(PTRACE_POKEDATA, m_pid, address, value);
        return 0;
    }

    int read_cstring() {
        return 0;
    }
};