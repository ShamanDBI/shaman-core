#ifndef H_MEMORY_ACCESSOR_H
#define H_MEMORY_ACCESSOR_H

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <spdlog/spdlog.h>
#include <fstream>

class Addr {

    uint8_t* m_data; // local buffer holding the data of tracee memory location
    uint64_t r_addr; // address in tracee memory space
    size_t m_size;

public:

    // memory size should be the multiple of memory pointer size
    // so for 64-bit system it should be multiple of 8 and for
    // 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size);
    ~Addr();

    Addr(Addr &addrObj);

    uint8_t* data() { return m_data; };

    void copy_buffer(const uint8_t* _buf, size_t _buf_len) {
        memcpy(m_data, _buf, _buf_len);
    }

    uint64_t raddr() { return r_addr; };
    size_t size() { return m_size; };
    void resize(uint64_t new_size);
    void setRemoteAddress(uint64_t _r_addr) { r_addr = _r_addr; }
    void clean();
    void print();

    void write_i8(int8_t value);
    void write_u8(uint8_t value);

    void write_u16(uint16_t value);
    void write_i16(int16_t value);

    void write_u32(uint32_t value);
    void write_i32(int32_t value);

    void write_u64(uint64_t value);
    void write_i64(int64_t value);

    int8_t read_i8();
    uint8_t read_u8();

    uint16_t read_u16();
    int16_t read_i16();

    uint32_t read_u32();
    int32_t read_i32();

    uint64_t read_u64();
    int64_t read_i64();

};

// using namespace std;

class RemoteMemory {

    pid_t m_pid;

#ifdef SUPPORT_MEM_FILE
    std::fstream* m_mem_file;
#endif

public:

    RemoteMemory(pid_t tracee_pid);
    ~RemoteMemory();

    int readRemoteAddrObj(Addr& dest, size_t readSize);
    int writeRemoteAddrObj(Addr& data, size_t writeSize);

    Addr* readPointerObj(uintptr_t _remote_addr, uint64_t _buffer_size);

    int read_cstring(Addr *data);
};

#endif