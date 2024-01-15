#include "syscall_mngr.hpp"
#include "syscall_injector.hpp"
#include "tracee.hpp"


// this system call which are related to filer operations
// https://linasm.sourceforge.net/docs/syscalls/filesystem.php
static const std::unordered_set<int16_t> FILE_OPTS_SYSCALL_ID{
	SysCallId::OPEN,
	SysCallId::CREAT,
	SysCallId::OPENAT,

	SysCallId::READ,
	SysCallId::READV,
	SysCallId::PREAD,
	SysCallId::PREADV,

	SysCallId::WRITE,
	SysCallId::WRITEV,
	SysCallId::PWRITE,
	SysCallId::PWRITEV,

	SysCallId::LSEEK,
	SysCallId::SENDFILE,

	SysCallId::CLOSE,

	SysCallId::MMAP2,
	SysCallId::MUNMAP,
	SysCallId::IOCTL,
	SysCallId::STAT};

// https://linasm.sourceforge.net/docs/syscalls/network.php
static const std::unordered_set<int16_t> NETWORK_OPTS_SYSCALL_ID{
	SysCallId::SOCKET,
	SysCallId::SOCKETPAIR,
	SysCallId::SETSOCKOPT,
	SysCallId::GETSOCKOPT,
	SysCallId::SHUTDOWN,
	SysCallId::GETPEERNAME,
	SysCallId::GETSOCKNAME,

	SysCallId::CONNECT,
	SysCallId::ACCEPT,
	SysCallId::LISTEN,
	SysCallId::BIND,

	SysCallId::READ,
	SysCallId::RECV,
	SysCallId::RECVFROM,
	SysCallId::RECVMSG,

	SysCallId::WRITE,
	SysCallId::SENDTO,
	SysCallId::SENDMSG,
	SysCallId::SENDFILE,

	SysCallId::SETHOSTNAME,
	SysCallId::SETDOMAINNAME,
};

static const std::unordered_set<int16_t> SHARED_MEMORY_OPTS_SYSCALL_ID{
	SysCallId::SHMGET,
	SysCallId::SHMCTL,
	SysCallId::SHMAT,
	SysCallId::SHMDT};

static const std::unordered_set<int16_t> PIPE_OPTS_SYSCALL_ID{
	SysCallId::PIPE,
	SysCallId::PIPE2,
	SysCallId::TEE,
	SysCallId::SPLICE,
	SysCallId::VMSPLICE,
};

static const std::unordered_set<int16_t> SEMAPHONES_OPTS_SYSCALL_ID{
	SysCallId::SEMGET,
	SysCallId::SEMCTL,
	SysCallId::SEMOP,
	SysCallId::SEMTIMEDOP};

static const std::unordered_set<int16_t> MSG_QUEUE_OPTS_SYSCALL_ID{
	SysCallId::MSGGET,
	SysCallId::MSGCTL,
	SysCallId::MSGSND,
	SysCallId::MSGRCV,
	SysCallId::MQ_OPEN,
	SysCallId::MQ_UNLINK,
	SysCallId::MQ_GETSETATTR,
	SysCallId::MQ_TIMEDSEND,
	SysCallId::MQ_TIMEDRECEIVE,
	SysCallId::MQ_NOTIFY};

static const std::unordered_set<int16_t> FUTEX_OPTS_SYSCALL_ID{
	SysCallId::FUTEX,
	SysCallId::SET_ROBUST_LIST,
	SysCallId::GET_ROBUST_LIST};

static const std::unordered_set<int16_t> PROCESS_OPTS_SYSCALL_ID{};

static const std::unordered_set<int16_t> SIGNALS_OPTS_SYSCALL_ID{
	SysCallId::KILL,
	SysCallId::TKILL,
	SysCallId::TGKILL,
	SysCallId::PAUSE,
	SysCallId::RT_SIGACTION,
	SysCallId::RT_SIGPROCMASK,
	SysCallId::RT_SIGPENDING,
	SysCallId::RT_SIGQUEUEINFO,
	// SysCallId::RT_TGSIGQUEUEINFO,
	SysCallId::RT_SIGTIMEDWAIT,
	SysCallId::RT_SIGSUSPEND,
	SysCallId::RT_SIGRETURN,
	SysCallId::SIGALTSTACK,
	// SysCallId::SIGNALFD,
	// SysCallId::SIGNALFD4,
	// SysCallId::EVENTFD,
	SysCallId::EVENTFD2,
	SysCallId::RESTART_SYSCALL,

};

static const std::unordered_set<int16_t> TIME_OPTS_SYSCALL_ID{

};

/**
 *  src : https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md
 *	arch	syscall NR	return	arg0	arg1	arg2	arg3	arg4	arg5
 *	arm		r7			r0		r0		r1		r2		r3		r4		r5
 *	arm64	x8			x0		x0		x1		x2		x3		x4		x5
 *	x86	    eax			eax		ebx		ecx		edx		esi		edi		ebp
 *	x86_64	rax			rax		rdi		rsi		rdx		r10		r8		r9
 */
void SyscallManager::readSyscallParams(TraceeProgram &traceeProg)
{
	SysCallId sys_id = SysCallId::NO_SYSCALL;
	int16_t call_id;
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	AMD64Register *amdRegObj;
	ARM64Register *arm64RegObj;
	X86Register *x86RegObj;
	ARM32Register *armRegObj;

	debug_opts.m_register.fetch();
	switch (traceeProg.m_target_desc.m_cpu_arch)
	{
	case CPU_ARCH::AMD64:
		amdRegObj = dynamic_cast<AMD64Register *>(&debug_opts.m_register);
		call_id = static_cast<int16_t>(amdRegObj->getRegIdx(SYSCALL_ID_AMD64));
		// m_log->debug("raw call id {}", call_id);
		sys_id = amd64_canonicalize_syscall(static_cast<AMD64_SYSCALL>(call_id));
		// m_log->debug("Syscall {}", sys_id.getString());
		m_cached_args.syscall_id = sys_id;

		m_cached_args.v_arg[0] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_0);
		m_cached_args.v_arg[1] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_1);
		m_cached_args.v_arg[2] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_2);
		m_cached_args.v_arg[3] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_3);
		m_cached_args.v_arg[4] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_4);
		m_cached_args.v_arg[5] = amdRegObj->getRegIdx(SYSCALL_AMD64_ARG_5);
		break;
	case CPU_ARCH::X86:
		m_log->error("Archictecture not Implemented!");
		x86RegObj = dynamic_cast<X86Register *>(&debug_opts.m_register);
		call_id = static_cast<int16_t>(armRegObj->getRegIdx(X86Register::EAX));
		sys_id = i386_canonicalize_syscall(call_id);
		m_cached_args.syscall_id = sys_id;
		break;
	case CPU_ARCH::ARM64:
		m_log->debug("reading prams");
		arm64RegObj = dynamic_cast<ARM64Register *>(&debug_opts.m_register);
		call_id = static_cast<int16_t>(arm64RegObj->getRegIdx(ARM64Register::X8));
		m_log->debug("raw call id {}", call_id);
		sys_id = arm64_canonicalize_syscall(static_cast<ARM64_SYSCALL>(call_id));
		m_cached_args.syscall_id = sys_id;

		m_cached_args.v_arg[0] = arm64RegObj->getRegIdx(ARM64Register::X0);
		m_cached_args.v_arg[1] = arm64RegObj->getRegIdx(ARM64Register::X1);
		m_cached_args.v_arg[2] = arm64RegObj->getRegIdx(ARM64Register::X2);
		m_cached_args.v_arg[3] = arm64RegObj->getRegIdx(ARM64Register::X3);
		m_cached_args.v_arg[4] = arm64RegObj->getRegIdx(ARM64Register::X4);
		m_cached_args.v_arg[5] = arm64RegObj->getRegIdx(ARM64Register::X5);
		break;
	case CPU_ARCH::ARM32:
		armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);

		call_id = static_cast<int16_t>(armRegObj->getRegIdx(ARM32Register::R7));
		m_log->debug("Raw Syscall id {}", call_id);
		sys_id = arm32_canonicalize_syscall(call_id);
		// m_log->debug("Syscall {}", sys_id.getString());
		m_cached_args.syscall_id = sys_id;

		m_cached_args.v_arg[0] = armRegObj->getRegIdx(ARM32Register::R0);
		m_cached_args.v_arg[1] = armRegObj->getRegIdx(ARM32Register::R1);
		m_cached_args.v_arg[2] = armRegObj->getRegIdx(ARM32Register::R2);
		m_cached_args.v_arg[3] = armRegObj->getRegIdx(ARM32Register::R3);
		m_cached_args.v_arg[4] = armRegObj->getRegIdx(ARM32Register::R4);
		m_cached_args.v_arg[5] = armRegObj->getRegIdx(ARM32Register::R5);
		// armRegObj->print();
		break;
	default:
		m_log->error("Invalid Archictecture");
		break;
	};
}

void SyscallManager::readRetValue(TraceeProgram &traceeProg)
{

	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	SysCallId sys_id = SysCallId::NO_SYSCALL;
	X86Register *x86RegObj = nullptr;
	AMD64Register *regObj = nullptr;
	ARM32Register *armRegObj = nullptr;
	ARM64Register *arm64RegObj = nullptr;

	switch (traceeProg.m_target_desc.m_cpu_arch)
	{
	case CPU_ARCH::X86:
		x86RegObj = dynamic_cast<X86Register *>(&debug_opts.m_register);
		x86RegObj->fetch();
		m_cached_args.v_rval = x86RegObj->getRegIdx(X86Register::EAX);
		break;
	case CPU_ARCH::AMD64:
		regObj = dynamic_cast<AMD64Register *>(&debug_opts.m_register);
		regObj->fetch();
		m_cached_args.v_rval = regObj->getRegIdx(AMD64Register::RAX);
		break;
	case CPU_ARCH::ARM32:
		armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
		armRegObj->fetch();
		svc_inst_addr = armRegObj->getProgramCounter() - 1;
		m_cached_args.v_rval = armRegObj->getRegIdx(ARM32Register::R0);
		// armRegObj->print();
		break;
	case CPU_ARCH::ARM64:
		arm64RegObj = dynamic_cast<ARM64Register *>(&debug_opts.m_register);
		arm64RegObj->fetch();
		m_cached_args.v_rval = arm64RegObj->getRegIdx(ARM64Register::X0);
		break;
	default:
		m_log->error("Invalid Archictecture");
		break;
	}
}

int SyscallManager::addFileOperationHandler(FileOperationTracer *file_opt_handler)
{
	m_pending_file_opts_handler.push_front(file_opt_handler);
	return 0;
}

int SyscallManager::addNetworkOperationHandler(NetworkOperationTracer *network_opt_handler)
{
	m_pending_network_opts_handler.push_front(network_opt_handler);
	return 0;
}

int SyscallManager::removeFileOperationHandler(FileOperationTracer *file_opt_handler)
{
	return 0;
}

int SyscallManager::addSyscallHandler(SyscallHandler *syscall_hdlr)
{
	m_syscall_handler_map.insert({syscall_hdlr->m_syscall_id.getIntValue(), syscall_hdlr});
	return 0;
}

int SyscallManager::removeSyscallHandler(SyscallHandler *syscall_hdlr)
{
	// m_syscall_handler_map[syscall_hdlr->syscall_id] = syscall_hdlr;
	return 0;
}

int SyscallManager::handleFileOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &syscall_args)
{
	int fd = static_cast<int>(syscall_args.v_arg[0]);

	auto file_ops_iter = m_active_file_opts_handler.find(fd);

	if (file_ops_iter == m_active_file_opts_handler.end())
	{
		// Not found!
		m_log->trace("No FileOperation is registered for fd {}", fd);
		return 0;
	}
	// File operation handler which has matched the file descriptor
	FileOperationTracer *file_ops_obj = file_ops_iter->second;

	switch (syscall_args.syscall_id.getValue())
	{
	case SysCallId::OPEN:
	case SysCallId::OPENAT:
	case SysCallId::CREAT:
		file_ops_obj->onOpen(sys_state, debug_opts, syscall_args);
		break;

	// All the syscall related to reading data from the file descriptor
	case SysCallId::READ:
	case SysCallId::READV:
	case SysCallId::PREAD:
	case SysCallId::PREADV:
		file_ops_obj->onRead(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::WRITE:
	case SysCallId::WRITEV:
	case SysCallId::PWRITE:
	case SysCallId::PWRITEV:
		file_ops_obj->onWrite(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::MMAP2:
		file_ops_obj->onMmap(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::MUNMAP:
		file_ops_obj->onMunmap(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::CLOSE:
		// Tracing this descriptor has to be release form here as the
		// resource is essentially destoryed
		file_ops_obj->onClose(sys_state, debug_opts, syscall_args);
		m_pending_file_opts_handler.push_front(file_ops_obj);
		m_active_file_opts_handler.erase(fd);
		break;
	case SysCallId::IOCTL:
		file_ops_obj->onIoctl(sys_state, debug_opts, syscall_args);
		break;
	default:
		file_ops_obj->onMisc(sys_state, debug_opts, syscall_args);
		break;
	}
	return 0;
}

int SyscallManager::handleNetworkOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &syscall_args)
{
	int fd = static_cast<int>(syscall_args.v_arg[0]);

	auto socket_opts_iter = m_active_network_opts_handler.find(fd);

	if (socket_opts_iter == m_active_network_opts_handler.end())
	{
		// Not found!
		m_log->trace("No NetworkOperationTracer is registered for fd {}", fd);
		return 0;
	}
	// Found
	NetworkOperationTracer *network_opts_obj = socket_opts_iter->second;

	switch (syscall_args.syscall_id.getValue())
	{
	case SysCallId::SOCKET:
	case SysCallId::SOCKETPAIR:
		network_opts_obj->onOpen(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::CONNECT:
		network_opts_obj->onConnect(sys_state, debug_opts, syscall_args);
		break;
	case SysCallId::ACCEPT:
		network_opts_obj->onAccept(sys_state, debug_opts, syscall_args);
		break;
	case SysCallId::LISTEN:
		network_opts_obj->onListen(sys_state, debug_opts, syscall_args);
		break;
	case SysCallId::BIND:
		network_opts_obj->onBind(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::IOCTL:
		network_opts_obj->onIoctl(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::READ:
	case SysCallId::RECV:
	case SysCallId::RECVFROM:
	case SysCallId::RECVMSG:
		network_opts_obj->onRecv(sys_state, debug_opts, syscall_args);
		break;

	case SysCallId::WRITE:
	case SysCallId::SENDTO:
	case SysCallId::SENDMSG:
	case SysCallId::SENDFILE:
		network_opts_obj->onSend(sys_state, debug_opts, syscall_args);
		break;
	default:
		network_opts_obj->onMisc(sys_state, debug_opts, syscall_args);
		break;
	}
	return 0;
}

int SyscallManager::onEnter(TraceeProgram &traceeProg)
{
	m_syscall_executed++;
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	m_log->debug("Syscall Inst {}", m_syscall_executed);
	readSyscallParams(traceeProg);
	// m_log->debug("ID {}", m_cached_args.getSyscallNo());

	// File operation handler
	if (FILE_OPTS_SYSCALL_ID.count(m_cached_args.getSyscallNo()))
	{
		m_log->trace("FILE OPT DETECED");
		handleFileOperation(SyscallState::ON_ENTER, debug_opts, m_cached_args);
	}

	if (NETWORK_OPTS_SYSCALL_ID.count(m_cached_args.getSyscallNo()))
	{
		handleNetworkOperation(SyscallState::ON_ENTER, debug_opts, m_cached_args);
	}

	// Find and invoke system call handler
	auto map_key = m_cached_args.getSyscallNo();
	auto sc_handler_iter = m_syscall_handler_map.equal_range(map_key);
	bool sys_hdl_not_fnd = true;

	for (auto it = sc_handler_iter.first; it != sc_handler_iter.second; ++it)
	{
		it->second->onEnter(m_cached_args);
		sys_hdl_not_fnd = false;
	}

	if (sys_hdl_not_fnd)
	{
		// Not found!
		m_log->trace("onEnter : No syscall handler is registered for this syscall number");
	}

	m_log->debug("NAME : -> {}", m_cached_args.syscall_id.getString());
	return 0;
}

int SyscallManager::onExit(TraceeProgram &traceeProg)
{
	DebugOpts &debug_opts = traceeProg.m_debug_opts;

	readRetValue(traceeProg);
	m_log->debug("NAME : <- {} 0x{:x}", m_cached_args.syscall_id.getString(), m_cached_args.v_rval);

	// Resource Tracing check has to be done on exit because if there is a
	// match you need resource identifier for futher tracing operation
	NetworkOperationTracer *network_opt = nullptr;

	// Check if any of the File Operation Tracer is getting created
	// if so then check the criteria and if 'onFilter' method returns
	// true then move the tracer from pending state to active state
	FileOperationTracer *f_opts = nullptr;

	int resource_fd = -1;

	// This is checking if new resource is getting created, if so
	// try to attach tracer to the file descriptor
	if (m_cached_args.syscall_id == SysCallId::OPENAT ||
		m_cached_args.syscall_id == SysCallId::OPEN ||
		m_cached_args.syscall_id == SysCallId::CREAT)
	{
		// File operation detector
		for (auto file_opt_iter = m_pending_file_opts_handler.begin();
			 file_opt_iter != m_pending_file_opts_handler.end();)
		{
			f_opts = *file_opt_iter;
			if (f_opts->onFilter(debug_opts, m_cached_args))
			{
				f_opts->onOpen(SyscallState::ON_EXIT, debug_opts, m_cached_args);
				// found the match, removing it from the list
				file_opt_iter = m_pending_file_opts_handler.erase(file_opt_iter);
				resource_fd = m_cached_args.v_rval;
				m_active_file_opts_handler[resource_fd] = f_opts;
			}
			else
			{
				++file_opt_iter;
			}
		}
	}

	// This is calling the active Resource Tracer
	if (FILE_OPTS_SYSCALL_ID.count(m_cached_args.getSyscallNo()))
	{
		m_log->debug("FILE OPT DETECED");
		handleFileOperation(SyscallState::ON_EXIT, debug_opts, m_cached_args);
	}

	// reset the value to use the same variable for network resource matching
	resource_fd = -1;

	if (m_cached_args.syscall_id == SysCallId::SOCKET ||
		m_cached_args.syscall_id == SysCallId::ACCEPT ||
		m_cached_args.syscall_id == SysCallId::CONNECT ||
		m_cached_args.syscall_id == SysCallId::LISTEN ||
		m_cached_args.syscall_id == SysCallId::BIND)
	{

		for (auto network_opt_iter = m_pending_network_opts_handler.begin();
			 network_opt_iter != m_pending_network_opts_handler.end();)
		{
			network_opt = *network_opt_iter;
			if (network_opt->onFilter(debug_opts, m_cached_args))
			{
				network_opt->onOpen(SyscallState::ON_EXIT, debug_opts, m_cached_args);
				// Once you we have found the resource we want to trace, we are not
				// removing it in case of network is becasue there will be a different
				// file descriptor used by the each client in case of server

				if (m_cached_args.syscall_id == SysCallId::SOCKET ||
					m_cached_args.syscall_id == SysCallId::ACCEPT)
				{
					// in-case of both of this syscall new fd are return
					// value
					resource_fd = m_cached_args.v_rval;
				}
				else
				{
					resource_fd = m_cached_args.v_arg[0];
				}
				m_log->info("Network Tracer match found for resource_fd {}", resource_fd);
				m_active_network_opts_handler[resource_fd] = network_opt;
			}
			++network_opt_iter;
		}
	}

	if (NETWORK_OPTS_SYSCALL_ID.count(m_cached_args.getSyscallNo()))
	{
		m_log->debug("NETWORK OPT DETECED");
		handleNetworkOperation(SyscallState::ON_EXIT, debug_opts, m_cached_args);
	}

	// Find and invoke system call handler
	auto syscall_map_key = m_cached_args.getSyscallNo();
	auto sys_hd_iter = m_syscall_handler_map.equal_range(syscall_map_key);
	bool sys_hdl_not_fnd = true;

	for (auto it = sys_hd_iter.first; it != sys_hd_iter.second; ++it)
	{
		it->second->onExit(m_cached_args);
		sys_hdl_not_fnd = false;
	}

	if (sys_hdl_not_fnd)
	{
		// Not found!
		m_log->trace("onExit : No syscall handler is registered for this syscall number");
	}
	return 0;
}

void SyscallInjector::injectSyscall(std::unique_ptr<SyscallInject> syscall_data)
{
	m_pending_syscall_inject.push_back(std::move(syscall_data));
}

/// @brief 'svc #0' instruction encoding
static const uint8_t arm_linux_le_svc[] = {0x00, 0x00, 0x00, 0xef};

BreakpointPtr SyscallInjector::setUp(std::string& mod_name, std::uintptr_t brkpt_offset)
{
	m_setup_breakpoint = new SyscallInjectorBreakpoint(mod_name, brkpt_offset, *this);
	return m_setup_breakpoint;
}

void SyscallInjector::execute(TraceeProgram &traceeProg)
{
	/**
	 * The technique which we are using is syscall hijack, where we change the parameter
	 * of the syscall to inject our syscall and capture the return value. Once we are
	 * done inject the call we resume from the previous syscall to continue execution
	 * without harming the original follow of the program.
	 */

	// Rest of the code is to handle `onEnter` state
	if (m_pending_syscall_inject.size() == 0)
	{
		return;
	}
	m_log->debug("Injecting syscall into the Tracee");
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	ARM32Register *armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
	armRegObj->fetch();

	// Pop one syscall which we want to inject
	auto inject_syscall = std::move(m_pending_syscall_inject.back());
	m_pending_syscall_inject.pop_back();
	inject_syscall->m_gp_register_copy = armRegObj->getRegisterCopy();

	std::uintptr_t bkpt_pc = armRegObj->getRegIdx(ARM32Register::PC) + 4;
	// const uint8_t* tmp_backup_byte = (uint8_t*)malloc(buf_backup_size);
    const uint32_t arm_inst_size = 4;
	m_log->error("Inst injection addr {:x}", bkpt_pc);
	Addr* inst_backup = debug_opts.m_memory.readPointerObj(bkpt_pc, arm_inst_size);
	inst_backup->copy_buffer(arm_linux_le_svc, sizeof(arm_linux_le_svc));
	debug_opts.m_memory.writeRemoteAddrObj(*inst_backup, sizeof(arm_linux_le_svc));
	// Update the sycall parameter
	switch (traceeProg.m_target_desc.m_cpu_arch)
	{

	case CPU_ARCH::ARM32:
		// Setup syscall ID
		armRegObj->setRegIdx(ARM32Register::R7, inject_syscall->m_syscall_id);
		// setup sycall parameter
		armRegObj->setRegIdx(ARM32Register::R0, inject_syscall->m_sys_args[0]);
		armRegObj->setRegIdx(ARM32Register::R1, inject_syscall->m_sys_args[1]);
		armRegObj->setRegIdx(ARM32Register::R2, inject_syscall->m_sys_args[2]);
		armRegObj->setRegIdx(ARM32Register::R3, inject_syscall->m_sys_args[3]);
		armRegObj->setRegIdx(ARM32Register::R4, inject_syscall->m_sys_args[4]);
		armRegObj->setRegIdx(ARM32Register::R5, inject_syscall->m_sys_args[5]);
		armRegObj->update();
		break;
	default:
		m_log->error("Syscall injection is not supported this CPU Architecture");
	}
	armRegObj->print();
	traceeProg.m_inject_call = std::move(inject_syscall);
	// traceeProg.toStateInject();
}

void SyscallInjector::cleanUp(TraceeProgram &traceeProg) {
	DebugOpts &debug_opts = traceeProg.m_debug_opts;
	ARM32Register *armRegObj = dynamic_cast<ARM32Register *>(&debug_opts.m_register);
	armRegObj->fetch();
	m_log->debug("Syscall Injection Done!");

	armRegObj->print();
	traceeProg.m_inject_call->m_ret_value = armRegObj->getRegIdx(ARM32Register::R0);
	m_log->debug("Inject Return value : {:x}", traceeProg.m_inject_call->m_ret_value);
	traceeProg.m_inject_call->onComplete();
	getchar();
	// Restore origingal state Where we hijacked the program flow
	armRegObj->restoreRegisterCopy(traceeProg.m_inject_call->m_gp_register_copy);
	armRegObj->print();
	// re-run the syscall to Prevent the program state
	armRegObj->setProgramCounter(armRegObj->getProgramCounter() - 4);
	armRegObj->update();
	traceeProg.m_inject_call.reset();
	getchar();
}
