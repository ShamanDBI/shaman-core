#include <ShamanDBA/config.hpp>
#include <netinet/in.h>
#include <sys/socket.h>
#include <CLI/CLI.hpp>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/fmt/bin_to_hex.h"
#include "spdlog/cfg/argv.h" // for loading levels from argv
#include "spdlog/cfg/env.h"

#include "ShamanDBA/breakpoint_reader.hpp"
#include "ShamanDBA/syscall.hpp"
#include "ShamanDBA/memory.hpp"
#include "ShamanDBA/debugger.hpp"
#include "ShamanDBA/utils.hpp"
#include "ShamanDBA/syscall_collections.hpp"
#include "ShamanDBA/syscall_injector.hpp"

#include <sys/mman.h>
#define ARM_MMAP2 192

void init_logger(std::string &log_file, int debug_log_level)
{
	spdlog::set_level(static_cast<spdlog::level::level_enum>(debug_log_level)); // Set global log level to debug
    spdlog::cfg::load_env_levels();

	spdlog::set_pattern("%^[%7l] [%9n]%$ %v");
	const char *log_names[] = {
		"main",
		"bkpt",
		"syscall",
		"res_tracer",
		"debugger",
		"disasm",
		"tracee"};

	for (int i = 0; i < (sizeof(log_names) / sizeof(const char *)); i++)
	{
		if (log_file.length() > 0)
		{
			auto main_logger = spdlog::basic_logger_mt(log_names[i], log_file);
		}
		else
		{
			auto console = spdlog::stdout_color_mt(log_names[i]);
		}
	}
}

class MmapSyscallInject : public SyscallInject
{

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main");
	AddrPtr m_mmap_addr = nullptr;

public:
	MmapSyscallInject(uint64_t mmap_size) : SyscallInject(ARM_MMAP2)
	{
		m_mmap_addr = new Addr();
		m_mmap_addr->setRemoteSize(mmap_size);
		setCallArg(0, 0);
		setCallArg(1, mmap_size);
		setCallArg(2, PROT_READ | PROT_WRITE);
		setCallArg(3, MAP_PRIVATE | MAP_ANONYMOUS);
		setCallArg(4, -1);
		setCallArg(5, 0);
	}

	void onComplete()
	{
		/**
		 * Check the return value an do some error handling and logging
		 */
		uintptr_t mmap_addr = m_ret_value;
		m_mmap_addr->setRemoteAddress(mmap_addr);
		m_log->info("Page allocated at address 0x{:x}", mmap_addr);
	}
};

int main(int argc, char **argv)
{

	CLI::App app{"Shaman DBI Framework"};

	std::string trace_log_path, app_log_path, basic_block_path;
	std::string coverage_output;
	std::string tmp_log;
	pid_t attach_pid{-1};
	std::vector<std::string> exec_prog;
	std::vector<std::string> brk_pnt_addrs;
	CPU_ARCH target_cpu_arch;
	CPU_MODE target_cpu_mode;
	std::string log_file_name;
	bool trace_syscalls = false;
	bool single_shot{false};
	bool follow_fork = false;
	int debug_log_level = 1;

	app.add_option("-l,--log", app_log_path, "write the shaman debug logs to the FILE");
	app.add_option("-o,--trace", trace_log_path, "write the tracee logs to the FILE");

	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");

	app.add_flag("-f,--follow", follow_fork, "follow the fork/clone/vfork syscalls");
	app.add_flag("-s,--syscall", trace_syscalls, "trace system calls");

	app.add_option("--debug", debug_log_level, "set debug level, for eg 0 for trace and 6 for critical");
	app.add_option("SPDLOG_LEVEL", tmp_log, "SPDLOG configuration");
	app.add_option("-e,--exec", exec_prog, "program to execute")
		->expected(-1); // 		->required();

	CLI11_PARSE(app, argc, argv);
	init_logger(app_log_path, debug_log_level);
	spdlog::cfg::load_argv_levels(argc, argv);

	auto log = spdlog::get("main");
	log->info("Welcome to Shaman!");

	TargetDescription targetDesc;

#if defined(SUPPORT_ARCH_X86)
	targetDesc.m_cpu_arch = CPU_ARCH::X86;
#elif defined(SUPPORT_ARCH_AMD64)
	targetDesc.m_cpu_arch = CPU_ARCH::AMD64;
#elif defined(SUPPORT_ARCH_ARM)
	targetDesc.m_cpu_arch = CPU_ARCH::ARM32;
#elif defined(SUPPORT_ARCH_ARM64)
	targetDesc.m_cpu_arch = CPU_ARCH::ARM64;
#else
	log->error("No Architecture is specified")
		exit(-1);
#endif

	Debugger debug(targetDesc);

	auto inject_mmap_sys = std::unique_ptr<MmapSyscallInject>(new MmapSyscallInject(0x2000));
	auto inject_mmap_sys2 = std::unique_ptr<MmapSyscallInject>(new MmapSyscallInject(0x5000));

	// debug.m_syscallMngr->injectSyscall(std::move(inject_mmap_sys));
	// debug.m_syscall_injector->injectSyscall(std::move(inject_mmap_sys));
	// debug.m_syscall_injector->injectSyscall(std::move(inject_mmap_sys2));

	// debug.addSyscallHandler(new OpenAt1Handler());
	// debug.addSyscallHandler(new OpenAt2Handler());
	// debug.addFileOperationHandler(new OverwriteFileData());
	// debug.addFileOperationHandler(new RandomeFileData(0xcafebabe));

	debug.addNetworkOperationHandler(new DataSocket());

	if (trace_syscalls)
	{
		debug.traceSyscall();
	}

	if (follow_fork)
	{
		debug.followFork();
	}

	if (attach_pid != -1)
	{
		log->info("Attaching to PID : {}", attach_pid);
		debug.attach(attach_pid);
	}
	else
	{
		debug.spawn(exec_prog);
	}

	debug.eventLoop();

	log->debug("Good Bye!");
}
