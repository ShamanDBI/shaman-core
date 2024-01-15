#include <coverage_trace_writer.hpp>

void CoverageTraceWriter::write_module_info()
{
    uint8_t mod_id = 0;
    uint16_t rec_type = static_cast<uint16_t>(CoverageRecordType::MODULE);
    for (std::string &mod_name : m_module_names)
    {
        m_trace_file.write((char *)&rec_type, sizeof(uint16_t));
        uint16_t mod_size = mod_name.size() & 0xffff;
        m_trace_file.write((char *)&mod_size, sizeof(uint16_t));
        m_trace_file.write(mod_name.c_str(), mod_size);
        m_trace_file.write((char *)&mod_id, sizeof(uint16_t));
    }
}

uint16_t CoverageTraceWriter::add_module(std::string module_name, uint64_t base_addr)
{
    m_module_names.push_back(module_name);
    m_module_id_map[module_name] = m_mod_curr_id;
    update_module_base_addr(module_name, base_addr);
    m_mod_curr_id++;
    return m_mod_curr_id - 1;
}

void CoverageTraceWriter::add_cov(pid_t tracee_pid, uint8_t module_id, uint64_t execution_addr)
{
    uint16_t rec_type = static_cast<uint16_t>(CoverageRecordType::BASIC_BLOCK);
    m_trace_file.write((char *)&rec_type, sizeof(uint16_t));
    m_trace_file.write((char *)&tracee_pid, sizeof(uint32_t));
    m_trace_file.write((char *)&module_id, sizeof(uint8_t));
    uint32_t exec_offset = (execution_addr - m_module_map[module_id]) & 0xFFFFFFFF;
    m_trace_file.write((char *)&exec_offset, sizeof(uint32_t));
}
