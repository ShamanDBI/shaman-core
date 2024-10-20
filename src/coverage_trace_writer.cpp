#include <coverage_trace_writer.hpp>

#undef MEM_PIPE_SHARED_DATA
//#define MEM_PIPE_SHARED_DATA

CoverageTraceWriter::CoverageTraceWriter(uint64_t pipe_id) {
    m_smem_pipe_id = pipe_id;
    m_ss_pipe = new SendPipe<DEFAULT_CHUNK_SIZE, DEFAULT_NUM_BUFFER>();
    MemPipeError res = m_ss_pipe->create(m_smem_pipe_id);

    if (res != MemPipeError::ResultOk)
    {
        spdlog::error("Error opening shared Memory!");
    }
#ifdef MEM_PIPE_SHARED_DATA
    m_chunk_writer = m_ss_pipe->allocateBuffer(false);
#endif
}

void CoverageTraceWriter::write_module_info()
{
    uint16_t mod_id = 0;
    uint16_t rec_type = static_cast<uint16_t>(CoverageRecordType::MODULE);
    for (std::string &mod_name : m_module_names)
    {
        uint16_t mod_size = mod_name.size() & 0xffff;
        mod_id = get_module_id(mod_name);
#ifdef MEM_PIPE_SHARED_DATA
        m_chunk_writer->send((uint8_t *)&rec_type, sizeof(uint16_t));
        m_chunk_writer->send((uint8_t *)&mod_size, sizeof(uint16_t));
        m_chunk_writer->send((uint8_t *)mod_name.c_str(), mod_size);
        m_chunk_writer->send((uint8_t *)&mod_id, sizeof(uint16_t));
#else
        m_trace_file.write((char *)&rec_type, sizeof(uint16_t));
        m_trace_file.write((char *)&mod_size, sizeof(uint16_t));
        m_trace_file.write(mod_name.c_str(), mod_size);
        m_trace_file.write((char *)&mod_id, sizeof(uint16_t));
#endif
    }
#ifdef MEM_PIPE_SHARED_DATA
    m_chunk_writer->drop();
    m_chunk_writer.reset();
    m_chunk_writer = m_ss_pipe->allocateBuffer(false);
#endif
}

uint16_t CoverageTraceWriter::add_module(std::string module_name, uint64_t base_addr)
{
    m_module_names.push_back(module_name);
    m_module_id_map[module_name] = m_mod_curr_id;
    update_module_base_addr(module_name, base_addr);
    m_mod_curr_id++;
    return m_mod_curr_id - 1;
}

void CoverageTraceWriter::record_cov(pid_t tracee_pid, uint16_t module_id, uint64_t execution_addr)
{
    uint16_t rec_type = static_cast<uint16_t>(CoverageRecordType::BASIC_BLOCK);

    uint32_t exec_offset = (execution_addr - m_module_map[module_id]) & 0xFFFFFFFF;
    int data_write = 0;
#ifdef MEM_PIPE_SHARED_DATA
    data_write += m_chunk_writer->send((uint8_t *)&rec_type, sizeof(uint16_t));
    data_write += m_chunk_writer->send((uint8_t *)&module_id, sizeof(uint16_t));
    data_write += m_chunk_writer->send((uint8_t *)&tracee_pid, sizeof(uint32_t));
    data_write += m_chunk_writer->send((uint8_t *)&exec_offset, sizeof(uint32_t));
#else
    m_trace_file.write((char *)&rec_type, sizeof(uint16_t));
    m_trace_file.write((char *)&tracee_pid, sizeof(uint32_t));
    m_trace_file.write((char *)&module_id, sizeof(uint8_t));
    m_trace_file.write((char *)&exec_offset, sizeof(uint32_t));
#endif
    m_cov_data_points_count += 1;

#ifdef MEM_PIPE_SHARED_DATA
    if(m_cov_data_points_count >= 50) {
        m_cov_data_points_count = 0;
        m_chunk_writer->drop();
        m_chunk_writer.reset();
        m_chunk_writer = m_ss_pipe->allocateBuffer(false);
    }
#endif
    // spdlog::warn("data write {}", data_write);
}
