#ifndef _MEMPIPE_H
#define _MEMPIPE_H

#include <atomic>
#include <memory>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define CURR_NUM_BUFFER 10
#define CURR_CHUNK_SIZE 1024

const uint64_t MEMPIPE_MAGIC = 0xef7bea3fb9ec4746;

enum class MemPipeError
{
    ErrShmOpen = 1,
    ErrSetMemorySize,
    ErrMapMemory,
    ErrPipeMismatch,
    ErrInvalidIPCConfig,
    ResultOk
};


template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
struct MemPipe
{
    // unique identifer representing our Shared memory
    uint64_t magic;

    // Size of each Chuck
    uint64_t chunk_size;

    // number of such Chunks
    uint32_t num_buffers;

    // unique id of the shared memory
    uint32_t m_uid;

    std::atomic_bool client_owned[NUM_BUFFERS];

    /// Holds the length of a transferred buffer. This must be populated prior
    /// to `client_owned` being set to `true`, and must be ordered correctly
    /// on the processor
    std::atomic_uint32_t client_len[NUM_BUFFERS];

    /// The sequence number for a given buffer, must be set prior to
    /// `client_owned` and ordered correctly on the processor
    std::atomic_uint64_t client_seq[NUM_BUFFERS];

    std::atomic_uint64_t cur_seq;

    uint8_t chunks[NUM_BUFFERS][CHUNK_SIZE];
};


template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
class ChunkWriter
{
    // Reference to the `MemPipe` we came from
    MemPipe<CHUNK_SIZE, NUM_BUFFERS> *m_mem_pipe;

    /// Accessor to the raw underlying bytes, points to the first byte of a
    /// [`Chunk`]'s raw data
    uint8_t *m_shm_raw_buffer;

    /// Buffer index in the [`RawMemPipe`]
    uint32_t m_idx;

    /// Tracks the number of initialized bytes in the chunk
    uint32_t m_written;

    /// Determines if we should block until the buffer is owned by us again
    bool m_blocking;

public:
    ChunkWriter(MemPipe<CHUNK_SIZE, NUM_BUFFERS> *_mem_pipe,
                uint8_t *_bytes, uint32_t _idx, bool _blocking)
        : m_mem_pipe(_mem_pipe), m_shm_raw_buffer(_bytes),
          m_idx(_idx), m_written(0), m_blocking(_blocking){};

    uint32_t send(uint8_t *buffer, uint32_t buf_size)
    {

        uint32_t remain = CHUNK_SIZE - m_written;
        uint32_t to_write = std::min(remain, buf_size);

        memcpy(m_shm_raw_buffer, buffer, to_write);

        m_written += to_write;
        return to_write;
    }

    void drop()
    {
        m_mem_pipe->client_len[m_idx].store(m_written, std::memory_order_relaxed);

        uint32_t seq_id = m_mem_pipe->cur_seq.fetch_add(1, std::memory_order_relaxed);
        m_mem_pipe->client_seq[m_idx].store(seq_id, std::memory_order_relaxed);

        m_mem_pipe->client_owned[m_idx].store(true, std::memory_order_release);

        if (m_blocking)
        {
            // Wait for the pipe to be owned by us again
            while (m_mem_pipe->client_owned[m_idx].load(std::memory_order_relaxed))
            {
                // spin for a while
                for (int i = 0; i < 1000; i++) {};
            }
        }
    }

    uint8_t *data() { return m_shm_raw_buffer; };
};


template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
class SendPipe
{
    uint64_t m_uid;
    MemPipe<CHUNK_SIZE, NUM_BUFFERS> *m_mem_pipe;

public:
    MemPipeError create(uint64_t pipe_id)
    {
        char shmpath[40] = {0};
        MemPipe<CHUNK_SIZE, NUM_BUFFERS> *shared_mmap;
        // uint64_t pipe_id = 0xbeef;
        snprintf(shmpath, sizeof(shmpath), "shaman_ipc_%lu", pipe_id);
        printf("Created Pipe ID : %s\n", shmpath);
        size_t mmap_size = sizeof(MemPipe<CHUNK_SIZE, NUM_BUFFERS>);
        shm_unlink(shmpath);

        int shm_fd = shm_open(shmpath, O_CREAT | O_EXCL | O_RDWR, 0600);

        if (shm_fd == -1)
            return MemPipeError::ErrShmOpen;

        if (ftruncate(shm_fd, sizeof(MemPipe<CHUNK_SIZE, NUM_BUFFERS>)) == -1)
            return MemPipeError::ErrSetMemorySize;

        /* Map the object into the caller's address space. */
        m_mem_pipe = (MemPipe<CHUNK_SIZE, NUM_BUFFERS> *)mmap(
            NULL, mmap_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED, shm_fd, 0);

        printf("Mmap create at addr %p of size %lx\n", m_mem_pipe, mmap_size);

        if (m_mem_pipe == MAP_FAILED)
        {
            m_mem_pipe = 0;
            return MemPipeError::ErrMapMemory;
        }

        // close(shm_fd);

        m_uid = pipe_id;

        m_mem_pipe->magic = MEMPIPE_MAGIC;
        m_mem_pipe->chunk_size = CHUNK_SIZE;
        m_mem_pipe->num_buffers = NUM_BUFFERS;
        m_mem_pipe->m_uid = m_uid;

        for (int i = 0; i < m_mem_pipe->num_buffers; i++)
        {
            m_mem_pipe->client_owned[i].store(false);
            m_mem_pipe->client_seq[i].store(0);
        }
        m_mem_pipe->cur_seq.store(0);

        return MemPipeError::ResultOk;
    };

    ~SendPipe()
    {
        int ret = munmap(m_mem_pipe, sizeof(MemPipe<CHUNK_SIZE, NUM_BUFFERS>));
        if (!ret)
        {
            printf("Error unmmaping the page");
        }
    }

    uint64_t uid() { return m_uid; };

    std::unique_ptr<ChunkWriter<CHUNK_SIZE, NUM_BUFFERS>> allocateBuffer(bool blocking)
    {
        while (true)
        {
            for (uint32_t i = 0; i < m_mem_pipe->num_buffers; i++)
            {
                if (!m_mem_pipe->client_owned[i].load(std::memory_order_acquire))
                {
                    printf("Found at index %d\n", i);
                    return std::unique_ptr<ChunkWriter<CHUNK_SIZE, NUM_BUFFERS>>(
                        new ChunkWriter<CHUNK_SIZE, NUM_BUFFERS>(
                            m_mem_pipe,
                            (uint8_t *)&m_mem_pipe->chunks[i],
                            i,
                            blocking));
                }
            }
        }
    };
};

typedef uint64_t Ticket;

typedef int (*DataProcFuncPtr)(uint8_t *, uint32_t) ;

/// The receiving side of a pipe, this will allow you to read sequenced data
/// as it was sent from a `SendPipe`
template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
class RecvPipe
{
    /// Reference to the memory pipe
    MemPipe<CHUNK_SIZE, NUM_BUFFERS> *m_mem_pipe;

    /// Current sequence index we're looking for
    std::atomic_uint64_t m_seq;

public:
    ~RecvPipe(){};

    MemPipeError open(uint64_t pipe_id)
    {
        char shmpath[40] = {0};
        uint64_t tmp_data[5] = {0};

        // MemPipe<CHUNK_SIZE, NUM_BUFFERS> *shared_mmap;
        snprintf(shmpath, sizeof(shmpath), "shaman_ipc_%lu", pipe_id);

        /* Open the existing shared memory object and map it
           into the caller's address space. */

        printf("Opened Pipe ID : %s\n", shmpath);
        int shm_fd = shm_open(shmpath, O_RDWR, 0);
        if (shm_fd == -1)
            return MemPipeError::ErrShmOpen;


        shm_unlink(shmpath);

        int read_val = read(shm_fd, tmp_data, sizeof(tmp_data));
        if (read_val != sizeof(tmp_data))
        {
            close(shm_fd);
            return MemPipeError::ErrPipeMismatch;
        }

        if (tmp_data[0] != MEMPIPE_MAGIC || tmp_data[1] != CHUNK_SIZE)
        {
            return MemPipeError::ErrPipeMismatch;
        }

        m_mem_pipe = (MemPipe<CHUNK_SIZE, NUM_BUFFERS> *)mmap(
            NULL,
            sizeof(MemPipe<CHUNK_SIZE, NUM_BUFFERS>), PROT_READ | PROT_WRITE,
            MAP_SHARED, shm_fd, 0);

        if (m_mem_pipe == MAP_FAILED)
        {
            m_mem_pipe = 0;
            return MemPipeError::ErrMapMemory;
        }

        close(shm_fd);

        return MemPipeError::ResultOk;
    };

    Ticket requestTicket() { return m_seq.fetch_add(1, std::memory_order_relaxed); };

    int try_recv(Ticket ticket, DataProcFuncPtr data_proc, Ticket * new_ticket)
    {
        for (int ii = 0; ii < m_mem_pipe->num_buffers; ii++)
        {
            if (!m_mem_pipe->client_owned[ii].load(std::memory_order_acquire))
            {
                continue;
            }

            // It's client owned, make sure it's the sequence we expect
            if (ticket != m_mem_pipe->client_seq[ii].load(std::memory_order_relaxed))
            {
                continue;
            }

            // Got the sequence we wanted, get the length
            uint32_t buffer_length = m_mem_pipe->client_len[ii].load(std::memory_order_relaxed);

            // Get a slice to the data
            uint8_t * buffer = m_mem_pipe->chunks[ii];
            int res = (*data_proc)(buffer, buffer_length);
            // Return zero mean successful
            if (!res) {
                m_mem_pipe->client_owned[ii].store(false, std::memory_order_release);
                *new_ticket = requestTicket();
            }
            return res;

        }
        return -1;
        
    };
};

#endif