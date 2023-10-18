#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "debugger.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"


class OverwriteFileData : public FileOperationTracer {

public:

	bool onFilter(DebugOpts* debug_opts, SyscallTraceData *sc_trace) {
		
		// spdlog::warn("onFilter!");

		switch(sc_trace->sc_id) {
		case NR_openat:
			Addr file_path_addr_t(sc_trace->v_arg[1], 100);
			debug_opts->m_memory->read(&file_path_addr_t, 100);
			if (strcmp(reinterpret_cast<char*>(file_path_addr_t.m_data), "/home/hussain/hi.txt") == 0) {
				spdlog::trace("We found the file we wanted to mess with!");
				return true;
			}
			break;
		}
		return false;
	}

	void onRead(SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace) {
		if(sys_state == SyscallState::ON_ENTER) {
			spdlog::debug("onRead: onEnter");
			int fd = static_cast<int>(sc_trace->v_arg[0]);
			uint64_t buf_len = sc_trace->v_arg[2];
			Addr buf(sc_trace->v_arg[1], buf_len);
			spdlog::warn("{} {} {}", fd, reinterpret_cast<char*>(buf.m_data), buf_len);
		} else {
			spdlog::warn("onRead: onExit");
			int fd = static_cast<int>(sc_trace->v_arg[0]);
			uint64_t buf_len = sc_trace->v_arg[2];
			Addr buf(sc_trace->v_arg[1], buf_len);
			debug_opts->m_memory->read(&buf, buf_len);
			printf("read %s\n", reinterpret_cast<char*>(buf.m_data));
			spdlog::warn("{} {} {}", fd, reinterpret_cast<char*>(buf.m_data), buf_len);
			memcpy(buf.m_data, "Malicous\x00", 9);
			debug_opts->m_memory->write(&buf, buf_len);
		}
	}

	void onClose(SyscallState sys_state, DebugOpts* debug_opts, SyscallTraceData *sc_trace) {
		spdlog::trace("onClose");
	}

};


class OpenAt1Handler : public SyscallHandler {

public:	
	OpenAt1Handler(): SyscallHandler(NR_openat) {}

	int onEnter(DebugOpts* debug_opts, SyscallTraceData* sc_trace) {
		spdlog::trace("onEnter : System call handler test");
		spdlog::trace("openat({:x}, {:x}, {}, {}) [{}]", sc_trace->v_arg[0], sc_trace->v_arg[1], sc_trace->v_arg[2],sc_trace->v_arg[3], sc_trace->v_rval);
		return 0;
	}
	int onExit(DebugOpts* debug_opts, SyscallTraceData* sc_trace) {
		spdlog::trace("onExit : System call handler test");
		spdlog::trace("openat({:x}, {:x}, {}, {}) [{}]", sc_trace->v_arg[0], sc_trace->v_arg[1], sc_trace->v_arg[2],sc_trace->v_arg[3], sc_trace->v_rval);
		return 0;
	}
};


class OpenAt2Handler : public SyscallHandler {

public:	
	OpenAt2Handler(): SyscallHandler(NR_openat) {}

	int onEnter(DebugOpts* debug_opts, SyscallTraceData* sc_trace) {
		spdlog::debug("onEnter : System call handler test again!");
		spdlog::debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace->v_arg[0], sc_trace->v_arg[1], sc_trace->v_arg[2],sc_trace->v_arg[3], sc_trace->v_rval);
		return 0;
	}

	int onExit(DebugOpts* debug_opts, SyscallTraceData* sc_trace) {
		spdlog::debug("onExit : System call handler test again!");
		spdlog::debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace->v_arg[0], sc_trace->v_arg[1], sc_trace->v_arg[2],sc_trace->v_arg[3], sc_trace->v_rval);
		return 0;
	}
};

#define REC_TYPE_NEXT -1
#define REC_TYPE_MODULE 0
#define REC_TYPE_FUNCTION 1
#define REC_TYPE_BB 2

struct CoverageParser {
	
	std::ifstream m_cov_info;
	bool is_single_shot = false;
	bool only_function = false;

	std::string* curr_mod_name_str = nullptr;
	// each module is iterated by each function
	// this variable stores the offset of the fuction relative to
	// module address
	uint64_t m_curr_func_offset = 0;
	// this variable store the offset of basic block relative to
	// to funtion
	uint32_t m_func_bb_count = 0;
	
	bool m_is_data_available = true;
	uint8_t m_record_type = -1;

	CoverageParser(std::string cov_path) {
		m_cov_info = std::ifstream(cov_path, std::ios::binary | std::ios::in );
	}

	std::string& getCurrentModuleName() {
		return *curr_mod_name_str;
	}

	CoverageParser& makeSingleShot() {
		is_single_shot = true;
		return *this;
	}

	Breakpoint* next() {
		auto log = spdlog::get("main_log");
		
		if (!m_is_data_available) {
			log->warn("No more data is avaliable");
			return nullptr;
		}
		Breakpoint* curr_brk_pnt;
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
			// log->info("Module {}", curr_mod_name_str->c_str());

			// Immeditialy follwing this record we have function record and
			// thats why haven't place break statement, and we are skipping
			// m_record_type parsing by following statement
			m_cov_info.seekg(sizeof(m_record_type), m_cov_info.cur);

		case REC_TYPE_FUNCTION:
			m_cov_info.read((char*)&curr_entry_size, sizeof(curr_entry_size));
			// log->info(" Function Size {} ", curr_entry_size);
			func_name = (char *) malloc(curr_entry_size + 1);
			m_cov_info.read(func_name, curr_entry_size);
			func_name[curr_entry_size] = 0;
			m_cov_info.read((char *)&m_curr_func_offset, sizeof(m_curr_func_offset));
			m_cov_info.read((char *)&m_func_bb_count, sizeof(m_func_bb_count));
			
			// Immedetially following function record we have basic block offset
			// relative to function offset, thats why I havn't place break statement
			m_record_type = REC_TYPE_BB;
			// log->info(" Function {} | offset - 0x{:x} | BB Count - {}", func_name, m_curr_func_offset, m_func_bb_count);

		case REC_TYPE_BB:
			if(m_func_bb_count > 0) {
				m_cov_info.read((char *)&curr_bb_offset, sizeof(curr_bb_offset));
				log->info("  BB 0x{:x} + 0x{:x} {}", m_curr_func_offset, curr_bb_offset, curr_mod_name_str->c_str());
				uint64_t brk_pnt_offset = m_curr_func_offset + curr_bb_offset;
				curr_brk_pnt = new Breakpoint(*curr_mod_name_str, brk_pnt_offset);
				// curr_brk_pnt->printDebug();
				if (is_single_shot)
					curr_brk_pnt->makeSingleShot();
				m_func_bb_count--;
			}
			if(m_func_bb_count == 0) {
				// once we are done parsing 
				m_record_type = REC_TYPE_NEXT;
				log->warn("No more breakpoint left to debug");
			}
			break;

		default:
			log->error("Invalid record while parsing file");
			break;
		}

		m_is_data_available = m_cov_info.peek() != EOF;
		return curr_brk_pnt;
	}
};

void parser_basic_block_file(Debugger& debug, std::string bb_path, bool is_single_shot) {
	
	bool should_cont = true;
	std::list<Breakpoint *> brk_offset;
	Breakpoint* new_brk_pt = nullptr;
	
	CoverageParser covParse(bb_path);
	
	if (is_single_shot)
		covParse.makeSingleShot();
	
	while (new_brk_pt = covParse.next())
	{
		// new_brk_pt = covParse.next();
		if(new_brk_pt) {
			brk_offset.push_back(new_brk_pt);
		}
	}

	spdlog::warn("Mod {} {}", covParse.getCurrentModuleName().c_str(), brk_offset.size());
	debug.m_breakpointMngr->m_pending[covParse.getCurrentModuleName()] = brk_offset;
}

int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	std::string trace_log_path, app_log_path, basic_block_path;
	pid_t attach_pid {-1};
	std::vector<std::string> exec_prog;
	std::vector<std::string> brk_pnt_addrs;
	std::string log_file_name;
	bool trace_syscalls = false;
	bool single_shot {false};
	bool follow_fork = false;
    
    app.add_option("-l,--log", app_log_path, "application debug logs");
	app.add_option("-o,--trace", trace_log_path, "output of the tracee logs");
	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");
	app.add_option("-b,--brk", brk_pnt_addrs, "Address of the breakpoints");
	app.add_option("-c,--cov-basic-block", basic_block_path, "Basic Block addresses which will be used for coverage collection");
	app.add_flag("--single-shot", single_shot, "Coverage collection should be single shot");
	app.add_option("-e,--exec", exec_prog, "program to execute");//->expected(-1)->required();
	app.add_flag("-f,--follow", follow_fork, "follow the fork/clone/vfork syscalls");
	app.add_flag("-s,--syscall", trace_syscalls, "trace system calls");

    CLI11_PARSE(app, argc, argv);


    if (app_log_path.length() > 0) {
    	auto main_logger = spdlog::basic_logger_mt("main_log", app_log_path);
    } else {
    	auto console = spdlog::stdout_color_mt("main_log");
    }

	auto log = spdlog::get("main_log");
    log->info("Welcome to Shaman!");
	
	Debugger debug;

	if (basic_block_path.length() > 0) {
		log->info("Processing basic block file {}", single_shot);
		parser_basic_block_file(debug, basic_block_path, single_shot);
		// return 0;
	}

	spdlog::set_level(spdlog::level::trace); // Set global log level to debug

	
	debug.addBreakpoint(brk_pnt_addrs);
	
	// debug.addSyscallHandler(new OpenAt1Handler());
	// debug.addSyscallHandler(new OpenAt2Handler());
	// debug.addFileOperationHandler(new OverwriteFileData());

	if(trace_syscalls) {
		debug.traceSyscall();
	}

	if(follow_fork) {
		debug.followFork();
	}

	if(attach_pid != -1) {
		log->info("Attaching to PID : {}", attach_pid);
		debug.attach(attach_pid);
	} else {
		debug.spawn(exec_prog);
	}

	debug.eventLoop();
	
	log->debug("Good Bye!");
}
