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


Addr::Addr(uint64_t _r_addr, size_t _size): m_size(_size), r_addr(_r_addr) {
    m_data = (uint8_t *) malloc(_size);
    // printf("mem alloc , %lu\n", size);
};

Addr::Addr(Addr &addrObj) {
    m_size = addrObj.m_size;
    r_addr = addrObj.r_addr;
    m_data = (uint8_t *) malloc(m_size);
    memcpy(m_data, addrObj.m_data, addrObj.m_size);
};

void Addr::print() {
    auto log = spdlog::get("main_log");
    log->trace("BKP {:x} VAL {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x} {:#04x}",
        r_addr,
        m_data[0], m_data[1], m_data[2], m_data[3], m_data[4]
        , m_data[5], m_data[6], m_data[7] );
};

Addr::~Addr() {
    free(m_data);
    m_data = NULL;
    r_addr = 0;
    m_size = 0;
}

void Addr::clean() {
    // set the data to zero
    memset(m_data, 0, m_size);
};

void Addr::resize(uint64_t new_size) {
    m_size = new_size;
};



RemoteMemory::RemoteMemory(pid_t tracee_pid) {
    m_pid = tracee_pid;

    char path[100];
    
    sprintf(path, "/proc/%d/mem", m_pid);
    
    m_mem_file = new std::fstream(path, 
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
    
    // spdlog::debug("read pid : {}", m_pid);
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
    // spdlog::debug("write pid : {}", m_pid);
    return bytes_write;
}

int RemoteMemory::read_cstring(Addr *data) {
    return 0;
}
