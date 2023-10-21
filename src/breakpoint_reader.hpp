#include <fstream>
#include "breakpoint.hpp"
#include "coverage_trace_writer.hpp"

#define REC_TYPE_NEXT -1
#define REC_TYPE_MODULE 0
#define REC_TYPE_FUNCTION 1
#define REC_TYPE_BB 2

struct BreakpointReader
{

	std::ifstream m_cov_info;
	bool is_single_shot = false;
	bool only_function = false;

	std::string *curr_mod_name_str = nullptr;
	// each module is iterated by each function
	// this variable stores the offset of the fuction relative to
	// module address
	uint64_t m_curr_func_offset = 0;
	// this variable store the offset of basic block relative to
	// to funtion
	uint32_t m_func_bb_count = 0;

	bool m_is_data_available = true;
	uint8_t m_record_type = -1;
	shared_ptr<CoverageTraceWriter> m_trace_writer;

	BreakpointReader(
		std::string cov_path,
		shared_ptr<CoverageTraceWriter> trace_writer)
			: m_trace_writer(trace_writer)
	{
		m_cov_info = std::ifstream(cov_path, std::ios::binary | std::ios::in);
	}

	std::string &getCurrentModuleName()
	{
		return *curr_mod_name_str;
	}

	BreakpointReader &makeSingleShot()
	{
		is_single_shot = true;
		return *this;
	}

	Breakpoint *next();
	~BreakpointReader()
	{
		m_cov_info.close();
	}
};

class BreakpointCoverage : public Breakpoint
{
	shared_ptr<CoverageTraceWriter> m_trace_writer;
	uint8_t m_module_id = 0;

public:
	BreakpointCoverage(
		shared_ptr<CoverageTraceWriter> trace_writer,
		std::string &modname,
		uintptr_t offset)
		: Breakpoint(modname, offset),
		  m_trace_writer(trace_writer)
	{
		m_module_id = m_trace_writer->get_module_id(modname);
	}

	virtual bool handle(DebugOpts *debug_opts) {
		m_trace_writer->add_cov(debug_opts->getPid(), m_module_id, m_addr);
	}

	virtual void setAddress(uintptr_t brkpnt_addr) {
		uintptr_t base_addr = brkpnt_addr - m_offset;
		m_trace_writer->update_module_base_addr(m_modname, base_addr);		
	}
};