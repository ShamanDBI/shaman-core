#ifndef H_MEMORY_ACCESSOR_H
#define H_MEMORY_ACCESSOR_H

#include <fstream>


class Addr {
public:
    uint8_t* m_data; // local buffer holding the data of tracee memory location
    uint64_t r_addr; // address in tracee memory space
    size_t m_size;
    
    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size);

    Addr(Addr &addrObj);

    void clean() ;

    void resize(uint64_t new_size);

    void print();

    ~Addr();
};

class RemoteMemory {

    pid_t m_pid;
    std::fstream* m_mem_file;

public:
    RemoteMemory(pid_t tracee_pid);
    
    ~RemoteMemory();
    void setPid(pid_t tracee_pid) { m_pid = tracee_pid;};
    int read(Addr *dest, size_t readSize);
    int write(Addr *data, size_t writeSize);
    int read_cstring(Addr *data);
};

#endif