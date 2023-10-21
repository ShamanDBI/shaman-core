#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "debugger.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "breakpoint_reader.hpp"

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


void parser_basic_block_file(Debugger& debug, std::string bb_path,
	bool is_single_shot, shared_ptr<CoverageTraceWriter> cov_trace_writer) {
	
	bool should_cont = true;
	std::list<Breakpoint *> brk_offset;
	Breakpoint* new_brk_pt = nullptr;
	
	std::string output_cov("exectrace.cov");
	BreakpointReader bkpt_reader_obj(bb_path, cov_trace_writer);
	
	if (is_single_shot)
		bkpt_reader_obj.makeSingleShot();
	
	while (new_brk_pt = bkpt_reader_obj.next())
	{
		// new_brk_pt = bkpt_reader_obj.next();
		if(new_brk_pt) {
			brk_offset.push_back(new_brk_pt);
		}
	}

	spdlog::warn("Mod {} {}", bkpt_reader_obj.getCurrentModuleName().c_str(), brk_offset.size());
	debug.m_breakpointMngr->m_pending[bkpt_reader_obj.getCurrentModuleName()] = brk_offset;
}

int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	std::string trace_log_path, app_log_path, basic_block_path;
	std::string coverage_output;
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
	app.add_option("--cov-out", coverage_output, "Output of the coverage data");	
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
	shared_ptr<CoverageTraceWriter> cov_trace_writer(nullptr);

	if (basic_block_path.length() > 0) {
		cov_trace_writer = make_shared<CoverageTraceWriter>(coverage_output);
		log->info("Processing basic block file {}", single_shot);
		parser_basic_block_file(debug, basic_block_path, single_shot, cov_trace_writer);
		// return 0;
	}

	spdlog::set_level(spdlog::level::debug); // Set global log level to debug

	
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

	// if (basic_block_path.length() > 0) {
	// 	cov_trace_writer->
	// }
	
	log->debug("Good Bye!");
}
