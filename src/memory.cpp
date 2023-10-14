// #include "memory.hpp"
#include <cstdint>
#include <cstdlib>
#include <sys/ptrace.h>
#include <cstring>
#include <sys/types.h>

#include <sys/user.h>
#include <sstream>
#include <elf.h>
#include "stdio.h"
#include "spdlog/spdlog.h"
#include "memory.hpp"

#include <fstream>
using namespace std;


RemoteMemory::RemoteMemory(pid_t tracee_pid) {
    m_pid = tracee_pid;

    char path[100];
    
    sprintf(path, "/proc/%d/mem", m_pid);
    
    m_mem_file = new fstream(path, 
        std::ios::binary | std::ios::in | std::ios::out);

    if (m_mem_file->is_open()) {
        spdlog::info("Mem file {} is open!", path);
    } else {
        spdlog::info("Error opening {} Mem file!", path);
    }
}

RemoteMemory::~RemoteMemory() {
    m_mem_file->close();
};


int RemoteMemory::read(Addr *dest, size_t readSize) {
    
    unsigned int bytes_read = 0;
    memset(dest->m_data, '\0', readSize);

    long * read_addr = (long *) dest->r_addr;
    long * copy_addr = (long *) dest->m_data;
    unsigned long ret;

    do {
        ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
        // printf("RD : %p\n", ret);
        *(copy_addr++) = ret;
        bytes_read += sizeof(long);
    } while(ret && bytes_read < (readSize - sizeof(long)));
    
    
    // m_mem_file->seekg(dest->r_addr);
    // m_mem_file->read((char *)dest->m_data, readSize);

    return bytes_read;

}

int RemoteMemory::write(Addr *dest, size_t writeSize) {

    uint32_t bytes_write = 0;
    long * write_addr = (long *) dest->r_addr;
    long * copy_addr = (long *) dest->m_data;
    long ret;
    
    do {
        ret = ptrace(PTRACE_POKEDATA, m_pid, (write_addr++), *(copy_addr++));
        // printf("WD : %lu \t", ret);
        bytes_write += sizeof(long);
        // printf("%lu %lu %d\n", bytes_write , (writeSize - sizeof(long)), ret > -1);
    } while((ret > -1 )&& bytes_write < (writeSize - sizeof(long)));
    
    // m_mem_file->seekg(dest->r_addr);
    // m_mem_file->write((char *)dest->m_data, writeSize);

    return bytes_write;
}

int RemoteMemory::read_cstring(Addr *data) {
    return 0;
}
