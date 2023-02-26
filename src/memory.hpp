#ifndef H_MEMORY_ACCESSOR_H
#define H_MEMORY_ACCESSOR_H

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>


struct Addr {

    uint8_t* addr; // local buffer holding the data of tracee memory location
    uint64_t r_addr; // address in tracee memory space
    size_t size;
    
    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size): size(_size), r_addr(_r_addr) {
        addr = (uint8_t *) malloc(_size);
        // printf("mem alloc , %lu\n", size);
    }

    void clean() {
        // set the data to zero
        memset(addr, 0, size);
    }

    void resize(uint64_t new_size) {
        size = new_size;
    }

    ~Addr() {
        free(addr);
    }
};


class RemoteMemory {

    pid_t m_pid;

public:
    RemoteMemory(pid_t tracee_pid) : m_pid(tracee_pid) {}

    int read(Addr *dest, size_t readSize);
    int write(Addr *data, size_t writeSize);
    int read_cstring(Addr *data);
};

#endif