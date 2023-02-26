#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "debugger.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

class RandFile : public FileOperationTracer {

public:

	bool onFilter(SyscallTraceData *sc_trace) {
		switch(sc_trace->sc_id) {
		case NR_openat:
			auto file_path_addr_t = Addr(sc_trace->v_arg[1], 100);
			m_debug_opts->m_memory->read(&file_path_addr_t, 100);
			if (strcmp(reinterpret_cast<char*>(file_path_addr_t.addr), "/home/hussain/hi.txt") == 0) {
				spdlog::warn("We foound it!");
				return true;
			}
			break;
		}
		return false;
	}

};

class MmapHandler : public SyscallHandler {

public:	
	MmapHandler(): SyscallHandler(NR_openat) {}

	int onExit(SyscallTraceData* sc_trace) {
		spdlog::debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace->v_arg[0], sc_trace->v_arg[1], sc_trace->v_arg[2],sc_trace->v_arg[3], sc_trace->v_rval);
		return 0;
	}
};

int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	std::string trace_log_path, app_log_path;
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
	app.add_option("-e,--exec", exec_prog, "program to execute")->expected(-1)->required();
	app.add_flag("-f,--follow", follow_fork, "follow the fork/clone/vfork syscalls");
	app.add_flag("-s,--syscall", trace_syscalls, "trace system calls");

    CLI11_PARSE(app, argc, argv);

    if (app_log_path.length() > 0) {
    	auto main_logger = spdlog::basic_logger_mt("main_log", app_log_path);
    } else {
    	auto console = spdlog::stdout_color_mt("main_log");
    }
	
    spdlog::info("Welcome to Shaman!");
	spdlog::set_level(spdlog::level::trace); // Set global log level to debug

	Debugger debug(brk_pnt_addrs);
	
	if(trace_syscalls) {
		debug.traceSyscall();
	}

	if(follow_fork) {
		debug.followFork();
	}

	// debug.parseBrk(brk_pnt_addrs);
	debug.spawn(exec_prog);
	debug.eventLoop();
	
	spdlog::debug("Good Bye!");
}
