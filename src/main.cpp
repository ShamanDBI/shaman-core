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

#define REC_TYPE_MODULE 0
#define REC_TYPE_FUNCTION 1

void parser_basic_block_file(Debugger& debug, std::string bb_path) {
	
	std::ifstream bb_info_file(bb_path, std::ios::binary | std::ios::in );
	auto log = spdlog::get("main_log");
	bool should_cont = true;
	uint8_t mod_type = 0;
	uint16_t mod_size = 0;
	char *mod_name = NULL;
	char *func_name = NULL;
	uint64_t func_offset = 0;

	uint32_t bb_count = 0;
	int32_t bb_offset = 0;

	std::string* mod_name_str = nullptr;
	std::list<Breakpoint *> brk_offset;
	int total_bkpt = 1000;
	while (should_cont)
	{

		bb_info_file.read((char*)&mod_type, sizeof(mod_type));
		
		if (mod_type == REC_TYPE_MODULE) {
			bb_info_file.read((char*)&mod_size, sizeof(mod_size));
			mod_name = (char *) malloc(mod_size + 1);
			bb_info_file.read(mod_name, mod_size);
			
			mod_name_str = new std::string(mod_name, mod_size);
			
			mod_name[mod_size] = 0;
			log->info("Module {}", mod_name_str->c_str());
		} else if (mod_type == REC_TYPE_FUNCTION) {
			bb_info_file.read((char*)&mod_size, sizeof(mod_size));
			// log->info(" Function Size {} ", mod_size);
			func_name = (char *) malloc(mod_size + 1);
			bb_info_file.read(func_name, mod_size);
			bb_info_file.read((char *)&func_offset, sizeof(func_offset));
			bb_info_file.read((char *)&bb_count, sizeof(bb_count));
			// log->info(" Function {} | offset - 0x{:x} | BB Count - {}", func_name, func_offset, bb_count);
			while(bb_count > 0) {
				bb_info_file.read((char *)&bb_offset, sizeof(bb_offset));
				// log->info("  BB 0x{:x}", bb_offset + func_offset);e

				Breakpoint* new_bb = new Breakpoint(*mod_name_str,
					func_offset + bb_offset// );
					, Breakpoint::BreakpointType::SINGLE_SHOT);
				brk_offset.push_back(new_bb);
				bb_count--;
				// total_bkpt--;

			}

		}
		if (total_bkpt < 0) {
			break;
		}

		should_cont = bb_info_file.peek() != EOF;
	}
	debug.m_breakpointMngr->m_pending[*mod_name_str] = brk_offset;
}

int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	std::string trace_log_path, app_log_path, basic_block_path;
	pid_t attach_pid {-1};
	std::vector<std::string> exec_prog;
	std::vector<std::string> brk_pnt_addrs;
	std::string log_file_name;
	bool trace_syscalls = false;
	bool follow_fork = false;
    
    app.add_option("-l,--log", app_log_path, "application debug logs");
	app.add_option("-o,--trace", trace_log_path, "output of the tracee logs");
	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");
	app.add_option("-b,--brk", brk_pnt_addrs, "Address of the breakpoints");
	app.add_option("-c,--basic-block", basic_block_path, "Basic Block addresses which will be used for coverage collection");
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
		log->info("Processing basic block file");
		parser_basic_block_file(debug, basic_block_path);
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

	debug.spawn(exec_prog);
	debug.eventLoop();
	
	log->debug("Good Bye!");
}
