#ifndef H_MEMORY_ACCESSOR_H
#define H_MEMORY_ACCESSOR_H

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>


struct Addr {

    uint8_t* m_data; // local buffer holding the data of tracee memory location
    uint64_t r_addr; // address in tracee memory space
    size_t m_size;
    
    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size): m_size(_size), r_addr(_r_addr) {
        m_data = (uint8_t *) malloc(_size);
        // printf("mem alloc , %lu\n", size);
    }

    Addr(Addr &addrObj) {
        m_size = addrObj.m_size;
        r_addr = addrObj.r_addr;
        m_data = (uint8_t *) malloc(m_size);
        memcpy(m_data, addrObj.m_data, addrObj.m_size);
    }

    void clean() {
        // set the data to zero
        memset(m_data, 0, m_size);
    }

    void resize(uint64_t new_size) {
        m_size = new_size;
    }

    void print() {
        auto log = spdlog::get("main_log");
        log->trace("BKP {:x} VAL {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
            r_addr,
            m_data[0], m_data[1], m_data[2], m_data[3], m_data[4]
            , m_data[5], m_data[6], m_data[7] );
    }

    ~Addr() {
        free(m_data);
        m_data = NULL;
        r_addr = 0;
        m_size = 0;
    }
};

using namespace std;

class RemoteMemory {

    pid_t m_pid;
    fstream* m_mem_file;

public:
    RemoteMemory(pid_t tracee_pid);
    
    ~RemoteMemory();
    void setPid(pid_t tracee_pid) { m_pid = tracee_pid;};
    int read(Addr *dest, size_t readSize);
    int write(Addr *data, size_t writeSize);
    int read_cstring(Addr *data);
};

#endif