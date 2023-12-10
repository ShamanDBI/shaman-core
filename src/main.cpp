#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "debugger.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "breakpoint_reader.hpp"
#include "syscall.hpp"
#include <netinet/in.h>
#include <sys/socket.h>
#include "memory.hpp"
#include "config.hpp"
#include "spdlog/fmt/bin_to_hex.h"

class DataSocket : public NetworkOperationTracer
{

	bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("Lets filter some stuff !");
		struct sockaddr_in *sock;
		struct sockaddr *client_sock_addr;
		int new_client_fd = -1;
		Addr socket_data(0, sizeof(struct sockaddr_in));
		Addr client_socket(0, sizeof(struct sockaddr));

		switch (sc_trace.getSyscallNo())
		{
		case SysCallId::SOCKET:
			m_log->warn("New Socket descriptor is created");
			break;
		case SysCallId::BIND:
			m_log->warn("Server : Binding calls");
			socket_data.setRemoteAddress(sc_trace.v_arg[1]);
			debugOpts.m_memory.readRemoteAddrObj(socket_data, sc_trace.v_arg[2]);
			sock = (struct sockaddr_in *)socket_data.data();
			m_log->warn("Socket IP {} port {}", sock->sin_addr.s_addr, ntohs(sock->sin_port));
			return true;
			break;
		case SysCallId::CONNECT:
			m_log->warn("Client : connecting to the server");
			return true;
			break;
		case SysCallId::ACCEPT:
			new_client_fd = sc_trace.v_rval;
			client_socket.setRemoteAddress(sc_trace.v_arg[1]);
			m_log->warn("Sock addr {:x} {}", sc_trace.v_arg[1], sc_trace.v_arg[2]);

			debugOpts.m_memory.readRemoteAddrObj(client_socket, sizeof(struct sockaddr));
			m_log->warn("Server : New Client connection with fd {}", new_client_fd);
			client_sock_addr = (struct sockaddr *)socket_data.data();
			m_log->warn("{}", spdlog::to_hex(
								  std::begin(client_sock_addr->sa_data),
								  std::begin(client_sock_addr->sa_data) + 14));
			return true;
			break;
		case SysCallId::LISTEN:
			m_log->warn("Server : Started listening...");
			break;
		default:
			break;
		}

		return false;
	}

	void onRecv(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		char malicious_text[] = "This is malicious data which is been intercepted and fille with!";
		if (sys_state == SyscallState::ON_EXIT)
		{
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_ptr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			uint64_t actual_read = sc_trace.v_rval;

			m_log->debug("onRead: {:x} {} -> {}", buf_ptr, buf_len, actual_read);
			Addr buf(buf_ptr, buf_len);
			debug_opts.m_memory.readRemoteAddrObj(buf, buf_len);
			buf.print();
			buf.copy_buffer((uint8_t *)malicious_text, buf_len);
			debug_opts.m_memory.writeRemoteAddrObj(buf, buf_len);
		}
	}

	void onSend(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		char malicious_text[] = "This is malicious data which is been intercepted and fille with!";
		if (sys_state == SyscallState::ON_ENTER)
		{
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_ptr = sc_trace.v_arg[1];
			uint64_t buf_len = sc_trace.v_arg[2];
			uint64_t actual_write = sc_trace.v_rval;

			m_log->debug("onWrite: {:x} {} -> {}", buf_ptr, buf_len, actual_write);
			Addr *buf = debug_opts.m_memory.readPointerObj(buf_ptr, buf_len);
			buf->print();
			memcpy(buf->data(), malicious_text, buf_len);
			debug_opts.m_memory.writeRemoteAddrObj(*buf, buf_len);
		}
	}
};

struct OverwriteFileData : public FileOperationTracer {

	bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace) {
		m_log->warn("onFilter!");

		switch (sc_trace.getSyscallNo()) {
		case SysCallId::OPENAT:
			Addr file_path_addr_t(sc_trace.v_arg[1], 100);
			debugOpts.m_memory.readRemoteAddrObj(file_path_addr_t, 100);
			m_log->trace("File path : {}", (char *)file_path_addr_t.data());
			if (strcmp(reinterpret_cast<char *>(file_path_addr_t.data()), "/home/hussain/hi.txt") == 0)
			{
				m_log->trace("We found the file we wanted to mess with!");
				return true;
			}
			break;
		}
		return false;
	}

	void onRead(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &sc_trace)
	{
		if (sys_state == SyscallState::ON_ENTER)
		{
			m_log->debug("onRead: onEnter");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr buf(sc_trace.v_arg[1], buf_len);
			m_log->warn("FD {} ptr 0x{:x} len 0x{:x}", fd, buf.raddr(), buf_len);
		}
		else
		{
			m_log->warn("onRead: onExit");
			int fd = static_cast<int>(sc_trace.v_arg[0]);
			uint64_t buf_len = sc_trace.v_arg[2];
			Addr buf(sc_trace.v_arg[1], buf_len);
			debug_opts.m_memory.readRemoteAddrObj(buf, buf_len);
			m_log->critical("Read : {}", reinterpret_cast<char*>(buf.data()));
			// m_log->warn("{} {} {}", fd, reinterpret_cast<char *>(buf.data()), buf_len);
			// const char * mal_cont = "Malicious\x00";	
			// memcpy(buf.data(), mal_cont, sizeof(mal_cont));
			const uint8_t mal_data[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
									   0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
			buf.copy_buffer(mal_data, sizeof(mal_data));
			debug_opts.m_memory.writeRemoteAddrObj(buf, sizeof(mal_data));
		}
	}

	// void onClose(SyscallState sys_state, DebugOpts& debug_opts, SyscallTraceData& sc_trace) {
	// 	m_log->trace("onClose");
	// }
};

class OpenAt1Handler : public SyscallHandler
{

public:
	OpenAt1Handler() : SyscallHandler(SysCallId::OPEN) {}

	int onEnter(SyscallTraceData &sc_trace)
	{
		m_log->debug("onEnter : System call handler test");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
	int onExit(SyscallTraceData &sc_trace)
	{
		m_log->debug("onExit : System call handler test");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
};

class OpenAt2Handler : public SyscallHandler
{

public:
	OpenAt2Handler() : SyscallHandler(SysCallId::OPENAT) {}

	int onEnter(SyscallTraceData &sc_trace)
	{
		m_log->debug("onEnter : System call handler test again!");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}

	int onExit(SyscallTraceData &sc_trace)
	{
		m_log->debug("onExit : System call handler test again!");
		m_log->debug("openat({:x}, {:x}, {}, {}) [{}]", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3], sc_trace.v_rval);
		return 0;
	}
};

void parser_basic_block_file(Debugger &debug, std::string bb_path,
							 bool is_single_shot, std::shared_ptr<CoverageTraceWriter> cov_trace_writer)
{

	bool should_cont = true;
	std::list<Breakpoint *> brk_offset;
	Breakpoint *new_brk_pt = nullptr;

	std::string output_cov("exectrace.cov");
	BreakpointReader bkpt_reader_obj(bb_path, cov_trace_writer);

	if (is_single_shot)
		bkpt_reader_obj.makeSingleShot();

	while (new_brk_pt = bkpt_reader_obj.next())
	{
		// new_brk_pt = bkpt_reader_obj.next();
		if (new_brk_pt)
		{
			brk_offset.push_back(new_brk_pt);
		}
	}

	// spdlog::warn("Mod {} {}", bkpt_reader_obj.getCurrentModuleName().c_str(), brk_offset.size());
	debug.m_breakpointMngr->m_pending[bkpt_reader_obj.getCurrentModuleName()] = brk_offset;
}

void init_logger(std::string &log_file, int debug_log_level)
{
	spdlog::set_level(static_cast<spdlog::level::level_enum>(debug_log_level)); // Set global log level to debug

	spdlog::set_pattern("%^[%6l] [%9n]%$ %v");
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

int main(int argc, char **argv)
{

	CLI::App app{"Shaman DBI Framework"};

	std::string trace_log_path, app_log_path, basic_block_path;
	std::string coverage_output;
	pid_t attach_pid{-1};
	std::vector<std::string> exec_prog;
	std::vector<std::string> brk_pnt_addrs;
	CPU_ARCH target_cpu_arch;
	CPU_MODE target_cpu_mode;
	std::string log_file_name;
	bool trace_syscalls = false;
	bool single_shot{false};
	bool follow_fork = false;
	int debug_log_level = 2;

	app.add_option("-l,--log", app_log_path, "application debug logs");
	app.add_option("-o,--trace", trace_log_path, "output of the tracee logs");

	app.add_option("-a,--arch", target_cpu_arch, "Architecture of the process");
	app.add_option("-m,--cpu-mode", target_cpu_mode, "Target architecture CPU mode");

	app.add_option("-b,--brk", brk_pnt_addrs, "Address of the breakpoints");

	app.add_option("-c,--cov-basic-block", basic_block_path, "Basic Block addresses which will be used for coverage collection");
	app.add_option("--cov-out", coverage_output, "Output of the coverage data");
	app.add_flag("--single-shot", single_shot, "Coverage collection should be single shot");

	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");

	app.add_flag("-f,--follow", follow_fork, "follow the fork/clone/vfork syscalls");
	app.add_flag("-s,--syscall", trace_syscalls, "trace system calls");

	app.add_option("--debug", debug_log_level, "set debug level, for eg 0 for trace and 6 for critical");
	app.add_option("-e,--exec", exec_prog, "program to execute")
		->expected(-1); // 		->required();

	CLI11_PARSE(app, argc, argv);

	init_logger(app_log_path, debug_log_level);

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
	std::shared_ptr<CoverageTraceWriter> cov_trace_writer(nullptr);

	if (basic_block_path.length() > 0)
	{
		cov_trace_writer = std::make_shared<CoverageTraceWriter>(coverage_output);
		log->info("Processing basic block file {}", single_shot);
		parser_basic_block_file(debug, basic_block_path, single_shot, cov_trace_writer);
		// return 0;
	}

	debug.addBreakpoint(brk_pnt_addrs);

	// debug.addSyscallHandler(new OpenAt1Handler());
	// debug.addSyscallHandler(new OpenAt2Handler());
	debug.addFileOperationHandler(new OverwriteFileData());
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

	if (basic_block_path.length() > 0)
	{
		cov_trace_writer->close();
	}

	log->debug("Good Bye!");
}
