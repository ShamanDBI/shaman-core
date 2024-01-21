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

#define DEFAULT_NUM_BUFFER 10
#define DEFAULT_CHUNK_SIZE 1024

/// @brief Magic ID for the Shared Memory
const uint64_t MEMPIPE_MAGIC = 0xef7bea3fb9ec4746;

/**
 * @brief Error Code when creating Shared Memory
 * 
 */
enum class MemPipeError
{
    /// @brief Error opening shared memory syscall
    ErrShmOpen = 1,

    /// @brief Unable to Create Shared Memory of desired size 
    ErrSetMemorySize,

    /// @brief Error mapping memory
    ErrMapMemory,

    /// @brief Error reading from Shared Memory File Descriptor
    ErrPipeMismatch,

    /// @brief Mismatching shared memory configuration
    ErrInvalidIPCConfig,

    /// @brief Success
    ResultOk
};

/**
 * @brief Shared Memory Buffer Mediator to allocate Shared buffer
 * 
 * @tparam CHUNK_SIZE Size of each buffer
 * @tparam NUM_BUFFERS Number of such buffer
 * 
 */
template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
struct MemPipe
{
    /// @brief unique identifer representing our Shared memory
    uint64_t magic;

    /// @brief Size of each Chuck
    uint64_t chunk_size;

    /// @brief number of such Chunks
    uint32_t num_buffers;

    /// @brief unique id of the shared memory
    uint32_t m_uid;

    std::atomic_bool client_owned[NUM_BUFFERS];

    /**
     * @brief Holds the length of a transferred buffer. This must be populated prior to
     * `client_owned` being set to `true`, and must be ordered correctly on the
     * processor
     */
    std::atomic_uint32_t client_len[NUM_BUFFERS];

    /// @brief The sequence number for a given buffer, must be set prior to
    /// `client_owned` and ordered correctly on the processor
    std::atomic_uint64_t client_seq[NUM_BUFFERS];

    /// @brief Currently processed sequence number
    std::atomic_uint64_t cur_seq;

    /// @brief Pointer to the Chunk Buffers
    uint8_t chunks[NUM_BUFFERS][CHUNK_SIZE];
};

/**
 * @brief Chunk Writer object
 * 
 * @tparam CHUNK_SIZE 
 * @tparam NUM_BUFFERS
 * 
 * @ingroup programming_interface 
 */
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

    /**
     * @brief Construct a new Chunk Writer object
     * 
     * @param _mem_pipe Metadata holding all the chunks
     * @param _bytes    Pointer to the writeable Chunk
     * @param _idx      Index in the chunk array
     * @param _blocking block the @ref drop function call
     */
    ChunkWriter(MemPipe<CHUNK_SIZE, NUM_BUFFERS> *_mem_pipe,
                uint8_t *_bytes, uint32_t _idx, bool _blocking)
        : m_mem_pipe(_mem_pipe), m_shm_raw_buffer(_bytes),
          m_idx(_idx), m_written(0), m_blocking(_blocking){};

    /**
     * @brief Copy the given buffer to the shared buffered
     * 
     * @param buffer    source buffer to copy
     * @param buf_size  size of the buffer to copy
     * @return uint32_t bytes left in the Shared Buffer
     */
    uint32_t send(uint8_t *buffer, uint32_t buf_size)
    {

        uint32_t remain = CHUNK_SIZE - m_written;
        uint32_t to_write = std::min(remain, buf_size);

        memcpy(m_shm_raw_buffer, buffer, to_write);

        m_written += to_write;
        return to_write;
    }

    /**
     * @brief The buffer is avalible for the Consumer
     * 
     */
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

    /**
     * @brief Give accesss to the Raw Buffer
     * 
     * @return uint8_t* Pointer to the Shared Buffer
     */
    uint8_t *data() { return m_shm_raw_buffer; };
};


/**
 * @brief Encapsulation for Producer Buffer
 * 
 * @tparam CHUNK_SIZE   Size of individual chunk
 * @tparam NUM_BUFFERS  Number of such chunks
 * 
 * @ingroup programming_interface 
 */
template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
class SendPipe
{
    /// @brief Unique Identifier for the Shared Memory
    uint64_t m_uid;

    /// @brief Metadata which has access to all the buffers
    MemPipe<CHUNK_SIZE, NUM_BUFFERS> *m_mem_pipe;

public:

    /**
     * @brief create a Shared Memory Segment
     * 
     * @param pipe_id 
     * @return MemPipeError 
     */
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

        close(shm_fd);

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

    /**
     * @brief Get one of the buffer avaliable for consumption
     * 
     * @param blocking  block the call until the same chunk is available
     * @return std::unique_ptr<ChunkWriter<CHUNK_SIZE, NUM_BUFFERS>> Chunk we want to process
     */
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
    }
};

/**
 * @brief Unique identifer for the Consumer Buffer
 */
typedef uint64_t Ticket;

/**
 * @brief Peek at the data before accepting it for processsing
 * 
 * @param buffer pointer to the buffer which has the data
 * @param buffer_size size of the buffer
 */
typedef int (*DataProcFuncPtr)(uint8_t * buffer, uint32_t buffer_size) ;

/**
 * @brief The receiving side of a pipe, this will allow you to read sequenced data as it was sent from a `SendPipe`
 * 
 * @tparam CHUNK_SIZE 
 * @tparam NUM_BUFFERS
 * 
 * @ingroup programming_interface 
 */
template <uint32_t CHUNK_SIZE, uint32_t NUM_BUFFERS>
class RecvPipe
{
    /// Reference to the memory pipe
    MemPipe<CHUNK_SIZE, NUM_BUFFERS> *m_mem_pipe;

    /// Current sequence index we're looking for
    std::atomic_uint64_t m_seq;

public:
    ~RecvPipe(){};

    /**
     * @brief Open an existing Shared Memory Buffer
     * 
     * @param pipe_id       Unique ID of the Shared Memory
     * @return MemPipeError Result of opening the Shared Memory
     */
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

    /**
     * @brief Request a new `Ticket` for processing new buffer
     * 
     * @return Ticket ticket for the New Request
     */
    Ticket requestTicket() { 
        return m_seq.fetch_add(1, std::memory_order_relaxed); 
    };

    /**
     * @brief Given a `Ticket` for a new buffer for processing
     * 
     * @param ticket Buffer corresponding to the ticket
     * @param data_proc Function to peek at the data
     * @param new_ticket New Ticket Which has to be submitted for the next request
     * @return int -1 failed to processs the Data, 0 for Successful Processing
     */
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
    }
};

#endif