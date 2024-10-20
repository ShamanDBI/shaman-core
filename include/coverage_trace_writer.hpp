#ifndef _H_COV_TRACE_WRITER
#define _H_COV_TRACE_WRITER

#include <fstream>
#include <unistd.h>
#include <map>
#include <vector>
#include <algorithm>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "mempipe.hpp"

#define REC_TYPE

enum CoverageRecordType: uint16_t {
    MODULE = 0,
    BASIC_BLOCK
};


/**
 * @brief This class write coverage trace to file
*/
class CoverageTraceWriter {

    /// @brief output of the 
    std::ofstream m_trace_file;
    
    std::vector<std::string> m_module_names;
    std::map<uint16_t, uint64_t> m_module_map;
    std::map<std::string, uint8_t> m_module_id_map;

    uintptr_t m_module_base_addr = 0;
    uint8_t m_mod_curr_id = 0;

    /// @brief shared memory pipe id
    uint64_t m_smem_pipe_id = 0;
    
    SendPipe<DEFAULT_CHUNK_SIZE, DEFAULT_NUM_BUFFER>* m_ss_pipe;
    
    uint64_t m_cov_data_points_count = 0;

    /// @brief shared memory where the coverage data is written to
    std::unique_ptr<ChunkWriter<DEFAULT_CHUNK_SIZE, DEFAULT_NUM_BUFFER>> m_chunk_writer 
        = std::unique_ptr<ChunkWriter<DEFAULT_CHUNK_SIZE, DEFAULT_NUM_BUFFER>>();

public:

    /**
     * @brief Construct a new Coverage Trace Writer object
     * 
     * @param output_path - file path where the covereage will be written
     */
    CoverageTraceWriter(std::string output_path) {
        m_trace_file = std::ofstream(output_path, std::ios::binary | std::ios::out | std::ios::trunc);
    }

    /**
     * @brief Construct a new Coverage Trace Writer object
     * 
     * Use this constructor when you are using shared memory to report
     * coverage information
     * 
     * @param pipe_id 
     */
    CoverageTraceWriter(uint64_t pipe_id);

    /**
     * @brief Write the module information in the stream, this information
     * can make the provides the base address of each modules and the covearage
     * information has the offset from that base. This approach will make the
     * coverage report consistent even in environment which has ASLR enabled.
     * 
     */
    void write_module_info();

    uint16_t get_module_id(std::string module_name) {
        return m_module_id_map[module_name];
    };

    void update_module_base_addr(std::string module_name, uint64_t base_addr) {
        uint8_t module_id = m_module_id_map[module_name];
        m_module_map[module_id] = base_addr;
    }

    uint16_t add_module(std::string module_name, uint64_t module_base_addr);

    /**
     * @brief this function is called everytime a breakpoint it hit, 
     * you can use this function to report the coverage data.
     * 
     * @param module_name 
     * @param module_base_addr  
     */
    void record_cov(pid_t tracee_pid, uint16_t module_id, uint64_t execution_addr);

    void close() {
        spdlog::warn("closing coverage file");
        m_trace_file.close();
    }

};

// typedef std::shared_ptr<CoverageTraceWriter> CoverageTraceWriterPtr;
#endif