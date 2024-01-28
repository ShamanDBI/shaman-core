#ifndef H_MEMORY_ACCESSOR_H
#define H_MEMORY_ACCESSOR_H

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <spdlog/spdlog.h>
#include <fstream>
#include "config.hpp"

/**
 * @brief Abstract for Memory Buffer in Tracee Process
 * 
 * The reason we need to abstract this because a buffer residing the
 * Tracee Process is combination of three value buffer
 * location(i.e. pointer address), the size of the buffer and
 * the buffer data itself.
 * 
 */
class Addr {

    /// @brief local buffer holding the data of tracee memory location
    uint8_t* m_data; 
    
    /// @brief address in tracee memory space
    uint64_t r_addr;

    /// @brief size of the buffer
    size_t m_size;

public:

    /// @brief Create plain object without allocating and memory
    Addr() = default;

    /// @brief memory size should be the multiple of memory pointer size
    /// so for 64-bit system it should be multiple of 8 and for
    /// 32-bit system it should be multiple of 4
    Addr(uint64_t _r_addr, size_t _size);
    
    ~Addr();

    Addr(Addr &addrObj);

    uint8_t* data() { return m_data; };

    /**
     * @brief Create a copy of the data buffer and return the memory
     * It is the responsibility of the caller to free the buffer
     * 
     * @return uint8_t* Pointer to the copy of the buffer
     */
    uint8_t* get_buffer_copy() {
        uint8_t * new_copy = reinterpret_cast<uint8_t *>(malloc(m_size));
        memcpy(new_copy, m_data, m_size);
        return new_copy;
    }

    /**
     * @brief Memory location fo the buffer in the Tracee Process
     * 
     * @return uint64_t Memory Location 
     */
    uint64_t raddr() { return r_addr; };

    /**
     * @brief Get Size of the Buffer in Tracee Process
     * 
     * @return size_t
     */
    size_t size() { return m_size; };
    
    /**
     * @brief Resize the memory buffer to new size
     * 
     * @param new_size size of the new buffer
     */
    void resize(uint64_t new_size);

    /// @brief Set the Address of the Tracee to which this memroy points to
    /// @param _r_addr Address in the Tracee Process memory

    /**
     * @brief Set the Address of the Tracee to which this memroy points to
     * 
     * @param _r_addr Address in the Tracee Process memory
     */
    void setRemoteAddress(uint64_t _r_addr) { r_addr = _r_addr; }

    void setRemoteSize(size_t r_size) { m_size = r_size;}

    /// @brief Set the entire Memory buffer to zero
    void clean();

    /// @brief Print the value memory of the on in the log
    void print();

    /**
     * @name Read
     * Read value to the Process memory
    */
    
    int8_t read_i8();
    uint8_t read_u8();

    uint16_t read_u16();
    int16_t read_i16();

    uint32_t read_u32();
    int32_t read_i32();

    uint64_t read_u64();
    int64_t read_i64();
    /// @}

    /**
     * @name Write
     * Write value to the Process memory
    */
    
    /// @brief Write one signed Bytes
    /// @param value byte to write
    void write_i8(int8_t value);

    /// @brief Write one unsigned byte
    /// @param value 
    void write_u8(uint8_t value);

    void write_u16(uint16_t value);
    void write_i16(int16_t value);

    void write_u32(uint32_t value);
    void write_i32(int32_t value);

    void write_u64(uint64_t value);
    void write_i64(int64_t value);
    
    /**
     * @brief Copy the buffer data in the Tracee Buffer
     * 
     * @param _buf pointer to the buffer to copy
     * @param _buf_len the length of the buffer to copy
     */
    void copy_buffer(const uint8_t* _buf, size_t _buf_len) {
        memcpy(m_data, _buf, _buf_len);
    }
    /// @}

    friend class RemoteMemory;
};

using AddrPtr = Addr *;


enum class MemoryOptResult {
    /// @brief Everything went as expecting
    ResultOk = 0,
    
    /// @brief Error while Reading to Tracee Process Memory
    ErrReading,
    
    /// @brief Error while writing to Tracee Process Memory
    ErrWriting,

    /// @brief The buffer povided the to read/write operation is not
    /// big enough
    ErrInsufficentBuffer,
};

/**
 * @brief Interface for Reading and Writing data in Tracee Memory
 * 
 * @ingroup platform_support
 * 
 */
class RemoteMemory {

    /// @brief Process ID of the Tracee in which read/write Operation will be done
    pid_t m_pid;

#ifdef SUPPORT_MEM_FILE
    std::fstream* m_mem_file;
    FILE* m_mem_fd;
#endif

public:

    /// @brief Create Object for Each Tracee
    /// @param tracee_pid 
    RemoteMemory(pid_t tracee_pid);

    ~RemoteMemory();

    /**
     * @brief Read data from the Tracee Process
     * 
     * @param dest 
     * @param readSize 
     * @return int 
     */
    int readRemoteAddrObj(Addr& dest, size_t readSize);

    int writeRemoteAddrObj(Addr& data, size_t writeSize);

    /**
     * @brief Read from the *Raw Address* in the Addr object
     * 
     * @param _remote_addr 
     * @param _buffer_size 
     * @return AddrPtr 
     */
    AddrPtr readPointerObj(uintptr_t _remote_addr, uint64_t _buffer_size);

    int read_cstring(Addr *data);
};

#endif