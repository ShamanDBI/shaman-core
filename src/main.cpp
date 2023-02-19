#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "debugger.hpp"

int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	std::string trace_log_path, app_log_path;
	pid_t attach_pid {-1};
	std::vector<std::string> exec_prog;
	std::vector<std::string> brk_pnt_addrs;
	

    app.add_option("-l,--log", app_log_path, "application debug logs");
	app.add_option("-o,--trace", trace_log_path, "output of the tracee logs");
	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");
	app.add_option("-b,--brk", brk_pnt_addrs, "Address of the breakpoints");
	// app.add_option("-f,--follow", brk_pnt_addrs, "follow the fork/clone/vfork syscalls");
	// app.add_option("-s,--syscall", brk_pnt_addrs, "trace system calls");
	app.add_option("-e,--exec", exec_prog, "program to execute")->expected(-1)->required();

    CLI11_PARSE(app, argc, argv);
	
    spdlog::info("Welcome to Shaman!");
	spdlog::set_level(spdlog::level::trace); // Set global log level to debug

	Debugger debug(brk_pnt_addrs);
	// debug.parseBrk(brk_pnt_addrs);
	debug.spawn(exec_prog);
	debug.eventLoop();
	
	spdlog::debug("Good Bye!");
}
