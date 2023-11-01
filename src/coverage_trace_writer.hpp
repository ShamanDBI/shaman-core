#ifndef _H_COV_TRACE_WRITER
#define _H_COV_TRACE_WRITER

#include <fstream>
#include <unistd.h>
#include <map>
#include <vector>
#include <algorithm>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#define REC_TYPE

enum CoverageRecordType: uint16_t {
    MODULE = 0,
    BASIC_BLOCK
};


/**
 * This class write coverage trace to file
*/
class CoverageTraceWriter {

    uintptr_t m_module_base_addr = 0;
    std::ofstream m_trace_file;
    std::vector<std::string> m_module_names;
    std::map<uint16_t, uint64_t> m_module_map;
    std::map<std::string, uint8_t> m_module_id_map;
    uint8_t m_mod_curr_id = 0;

public:
    CoverageTraceWriter(std::string output_path) {
        m_trace_file = std::ofstream(output_path, std::ios::binary | std::ios::out);
    }

    void write_module_info();

    uint8_t get_module_id(std::string module_name) {
        return m_module_id_map[module_name];
    };

    void update_module_base_addr(std::string module_name, uint64_t base_addr) {
        uint8_t module_id = m_module_id_map[module_name];
        m_module_map[module_id] = base_addr;
    }

    uint16_t add_module(std::string module_name, uint64_t module_base_addr);

    void add_cov(pid_t tracee_pid, uint8_t module_id, uint64_t execution_addr);

    ~CoverageTraceWriter() {
        spdlog::warn("closing coverage file");
        m_trace_file.close();
    }
};

// typedef std::shared_ptr<CoverageTraceWriter> CoverageTraceWriterPtr;
#endif