#include <sys/ptrace.h>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "memory.hpp"


Addr::Addr(uint64_t _r_addr, size_t _size)
    : m_size(_size), r_addr(_r_addr) {
        if(_size < 8) {
            _size = 8;
        }
        m_data = (uint8_t *) malloc(_size);
}

Addr::Addr(Addr &addrObj) {
    m_size = addrObj.m_size;
    r_addr = addrObj.r_addr;
    m_data = (uint8_t *) malloc(m_size);
    memcpy(m_data, addrObj.m_data, addrObj.m_size);
}

void Addr::print() {
    auto log = spdlog::get("main");
    std::vector<uint8_t> xx(m_size);
    memcpy(xx.data(), m_data, m_size);
    log->warn("{}", spdlog::to_hex(xx));
}

Addr::~Addr() {
    free(m_data);
    m_data = NULL;
    r_addr = 0;
    m_size = 0;
}

void Addr::clean() {
    // set the data to zero
    memset(m_data, 0, m_size);
}

void Addr::resize(uint64_t new_size) {
    m_size = new_size;
    m_data = (uint8_t *)realloc(m_data, new_size);
}

int8_t Addr::read_i8() {
    return m_data[0];
}

uint8_t Addr::read_u8() {
    return m_data[0];
}

void Addr::write_i8(int8_t value) {
    m_data[0] = value;
}

void Addr::write_u8(uint8_t value) {
    m_data[0] = value;
}

void Addr::write_u16(uint16_t value) {
    m_data[0] = (uint8_t) value;
    m_data[1] = (uint8_t) (value >> 8);
}

void Addr::write_i16(int16_t value) {
    write_i16(value);
}

void Addr::write_u32(uint32_t value) {
    m_data[0] = (uint8_t) value;
    m_data[1] = (uint8_t) (value >> 8);
    m_data[2] = (uint8_t) (value >> 16);
    m_data[3] = (uint8_t) (value >> 24);
}

void Addr::write_i32(int32_t value) {
    write_u32(value);
}

void Addr::write_u64(uint64_t value) {
    m_data[0] = (uint8_t) value;
    m_data[1] = (uint8_t) (value >> 8);
    m_data[2] = (uint8_t) (value >> 16);
    m_data[3] = (uint8_t) (value >> 24);
    m_data[4] = (uint8_t) (value >> 32);
    m_data[5] = (uint8_t) (value >> 40);
    m_data[6] = (uint8_t) (value >> 48);
    m_data[7] = (uint8_t) (value >> 56);
}

void Addr::write_i64(int64_t value) {
    write_u64(value);
}

uint16_t Addr::read_u16() {
    uint16_t value = 0;
    value |= (uint16_t) m_data[0];
    value |= (uint16_t) m_data[1] << 8;
    return value;
}

int16_t Addr::read_i16() {
    
    int16_t value = 0;
    value |= (int16_t) m_data[0];
    value |= (int16_t)(int8_t) m_data[3] << 8;
    return value;
}

uint32_t Addr::read_u32() {
    uint32_t value = 0;
    value |= (uint32_t) m_data[0];
    value |= (uint32_t) m_data[1] << 8;
    value |= (uint32_t) m_data[2] << 16;
    value |= (uint32_t) m_data[3] << 24;
    return value;
}

int32_t Addr::read_i32() {
    
    int32_t value = 0;
    value |= (int32_t) m_data[0];
    value |= (int32_t) m_data[1] << 8;
    value |= (int32_t) m_data[2] << 16;
    value |= (int32_t)(int8_t) m_data[3] << 24;

    return value;
}

uint64_t Addr::read_u64() {
    uint64_t value = 0;
    value |= (uint64_t) m_data[0];
    value |= (uint64_t) m_data[1] << 8;
    value |= (uint64_t) m_data[2] << 16;
    value |= (uint64_t) m_data[3] << 24;
    value |= (uint64_t) m_data[4] << 32;
    value |= (uint64_t) m_data[5] << 40;
    value |= (uint64_t) m_data[6] << 48;
    // Sign-extend the most significant byte
    value |= (uint64_t) m_data[7] << 56;
    return value;
}

int64_t Addr::read_i64() {
    int64_t value = 0;
    value |= (int64_t) m_data[0];
    value |= (int64_t) m_data[1] << 8;
    value |= (int64_t) m_data[2] << 16;
    value |= (int64_t) m_data[3] << 24;
    value |= (int64_t) m_data[4] << 32;
    value |= (int64_t) m_data[5] << 40;
    value |= (int64_t) m_data[6] << 48;
    // Sign-extend the most significant byte
    value |= (int64_t)(int8_t) m_data[7] << 56;
    return value;
}

// ------------- REMOTE MEMORY MANAGEMENT ---------------

RemoteMemory::RemoteMemory(pid_t tracee_pid) {
    m_pid = tracee_pid;

#ifdef SUPPORT_MEM_FILE
    char path[100];
    
    sprintf(path, "/proc/%d/mem", m_pid);
    m_mem_file = new std::fstream(path, 
        std::ios::binary | std::ios::in | std::ios::out);

    if (m_mem_file->is_open()) {
        spdlog::info("Mem file {} is open!", path);
    } else {
        spdlog::info("Error opening {} Mem file!", path);
    }
#endif
}

RemoteMemory::~RemoteMemory() {
#ifdef SUPPORT_MEM_FILE
    m_mem_file->close();
    m_mem_file = nullptr;
#endif
    m_pid = 0;
};


int RemoteMemory::readRemoteAddrObj(Addr& dest, size_t readSize) {
    
#ifdef SUPPORT_MEM_FILE
    m_mem_file->seekg(dest.r_addr);
    m_mem_file->read((char *)m_data, readSize);
#else
    unsigned int bytes_read = 0;
    if(readSize < 8) {
        readSize = 8;
    }

    memset(dest.data(), '\0', readSize);

    long * read_addr = (long *) dest.raddr();
    long * copy_addr = (long *) dest.data();
    unsigned long ret;

    do {
        ret = ptrace(PTRACE_PEEKTEXT, m_pid, (read_addr++), NULL);
        // printf("RD : %p\n", ret);
        *(copy_addr++) = ret;
        bytes_read += sizeof(long);
    } while(ret && bytes_read < (readSize - sizeof(long)));
    
    // spdlog::debug("read pid : {}", m_pid);

#endif
    return bytes_read;

}

int RemoteMemory::writeRemoteAddrObj(Addr& dest, size_t writeSize) {

#ifdef SUPPORT_MEM_FILE
    // m_mem_file->seekg(dest.r_addr);
    // m_mem_file->write((char *)m_data, writeSize);
#else
    uint32_t bytes_write = 0;
    long * write_addr = (long *) dest.raddr();
    long * copy_addr = (long *) dest.data();
    long ret;
    
    do {
        ret = ptrace(PTRACE_POKEDATA, m_pid, (write_addr++), *(copy_addr++));
        // printf("WD : %lu \t", ret);
        bytes_write += sizeof(long);
        // printf("%lu %lu %d\n", bytes_write , (writeSize - sizeof(long)), ret > -1);
    } while((ret > -1 )&& bytes_write < (writeSize - sizeof(long)));
    
#endif
    // spdlog::debug("write pid : {}", m_pid);

    return bytes_write;
}

Addr* RemoteMemory::readPointerObj(uintptr_t _remote_addr, uint64_t _buffer_size) {
    Addr* remote_addr_obj = new Addr(_remote_addr, _buffer_size);
    readRemoteAddrObj(*remote_addr_obj, _buffer_size);
    return remote_addr_obj;
}

int RemoteMemory::read_cstring(Addr *data) {
    return 0;
}
