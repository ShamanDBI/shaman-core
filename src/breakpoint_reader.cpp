#include "breakpoint_reader.hpp"

Breakpoint* BreakpointReader::next() {
    auto log = spdlog::get("bkpt");
    
    if (!m_is_data_available) {
        log->debug("No more data is avaliable");
        return nullptr;
    }
    BreakpointCoverage* curr_brk_pnt;
    uint16_t curr_entry_size = 0;
    char *mod_name = NULL;
    char *func_name = NULL;
    int32_t curr_bb_offset = 0;

    if (m_record_type != REC_TYPE_BB) {
        m_cov_info.read((char*)&m_record_type, sizeof(m_record_type));
    }

    switch (m_record_type) {
    case REC_TYPE_MODULE:
        m_cov_info.read((char*)&curr_entry_size, sizeof(curr_entry_size));
        mod_name = (char *) malloc(curr_entry_size + 1);
        m_cov_info.read(mod_name, curr_entry_size);
        mod_name[curr_entry_size] = 0;
        curr_mod_name_str = new std::string(mod_name, curr_entry_size);
        log->trace("Module {}", curr_mod_name_str->c_str());
        m_trace_writer->add_module(*curr_mod_name_str, 0);
        // Immeditialy follwing this record we have function record and
        // thats why haven't place break statement, and we are skipping
        // m_record_type parsing by following statement
        m_cov_info.seekg(sizeof(m_record_type), m_cov_info.cur);
        // break statement is skipped intentionally
    case REC_TYPE_FUNCTION:
        m_cov_info.read((char*)&curr_entry_size, sizeof(curr_entry_size));
        // log->info(" Function Size {} ", curr_entry_size);
        func_name = (char *) malloc(curr_entry_size + 1);
        m_cov_info.read(func_name, curr_entry_size);
        func_name[curr_entry_size] = 0;
        m_cov_info.read((char *)&m_curr_func_offset, sizeof(m_curr_func_offset));
        m_cov_info.read((char *)&m_func_bb_count, sizeof(m_func_bb_count));
        
        log->trace(" Function {} | offset - 0x{:x} | BB Count - {}", func_name, m_curr_func_offset, m_func_bb_count);
        
        // Immedetially following function record we have basic block offset
        // relative to function offset, thats why I havn't place break statement
        m_record_type = REC_TYPE_BB;
        // break statement is skipped intentionally
    case REC_TYPE_BB:
        if(m_func_bb_count > 0) {
            m_cov_info.read((char *)&curr_bb_offset, sizeof(curr_bb_offset));
            log->trace("  BB 0x{:x} + 0x{:x} {}", m_curr_func_offset, curr_bb_offset, curr_mod_name_str->c_str());
            uint64_t brk_pnt_offset = m_curr_func_offset + curr_bb_offset;
            if(curr_bb_offset == 0) {
                // this is a function entry-point block
            }
            curr_brk_pnt = new BreakpointCoverage(m_trace_writer, *curr_mod_name_str, brk_pnt_offset);
            // curr_brk_pnt->printDebug();
            if (is_single_shot) {
                curr_brk_pnt->makeSingleShot();
            } else {
                curr_brk_pnt->setMaxHitCount(100);
            }
            m_func_bb_count--;
        }
        if(m_func_bb_count == 0) {
            // once we are done parsing 
            m_record_type = REC_TYPE_NEXT;
            // log->trace("No more breakpoint left to debug");
        }
        break;

    default:
        log->error("Invalid record while parsing file");
        break;
    }

    m_is_data_available = m_cov_info.peek() != EOF;
    if (m_is_data_available == false) {
        // we have parsed all the modules, we are call this
        // function to write the module information to output 
        // data trace file
        m_trace_writer->write_module_info();
    }
    return curr_brk_pnt;
}
