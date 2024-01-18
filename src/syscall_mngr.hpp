#ifndef H_SYSCALL_HANDLER_H
#define H_SYSCALL_HANDLER_H

#include <unordered_set>
#include <map>
#include <list>
#include <spdlog/spdlog.h>

#include "syscall.hpp"
#include "debug_opts.hpp"

#define SYSCALL_ID_AMD64    15 	  // INTEL_X64_REGS::ORIG_RAX
#define SYSCALL_AMD64_ARG_0 14    // INTEL_X64_REGS::RDI
#define SYSCALL_AMD64_ARG_1 13    // INTEL_X64_REGS::RSI
#define SYSCALL_AMD64_ARG_2 12    // INTEL_X64_REGS::RDX
#define SYSCALL_AMD64_ARG_3  7    // INTEL_X64_REGS::R10
#define SYSCALL_AMD64_ARG_4  9    // INTEL_X64_REGS::R8
#define SYSCALL_AMD64_ARG_5  8    // INTEL_X64_REGS::R9
#define SYSCALL_AMD64_RET   10    // INTEL_X64_REGS::RAX


class TraceeProgram;

/// @brief The struct is used to store syscall data while the data is been
/// processed by the Kernel, i.e. `onEnter` to `onExit`
struct SyscallTraceData
{
	pid_t m_pid; /* If 0, this syscall trace data is free */

	// System call number which is converted to canonical system call
	SysCallId syscall_id;

	/** @brief syscall number observer by the Register */
	int16_t orig_syscall_number;
	
	/** @brief return value of the system call */
	int64_t v_rval;

	/// @brief number of argument this syscall takes
	uint8_t nargs; 
	
	/// @brief argument of the syscall
	uint64_t v_arg[SYSCALL_MAXARGS];

	SyscallTraceData()
	{
		reset();
	}

	/// @brief reset the object values to invalid state
	void reset()
	{
		syscall_id = SysCallId::NO_SYSCALL;
		nargs = 0;
		v_rval = 0;
		m_pid = 0;
		memset(v_arg, 0, sizeof(v_arg));
	}

	/// @brief Copy Constructor
	/// @param otherSyscall - the object you want to copy
	SyscallTraceData(const SyscallTraceData &otherSyscall) : m_pid(otherSyscall.m_pid)
	{
		memcpy(&v_arg, otherSyscall.v_arg, sizeof(v_arg));
		v_rval = otherSyscall.v_rval;
		syscall_id = otherSyscall.syscall_id;
		nargs = otherSyscall.nargs;
		m_pid = otherSyscall.m_pid;
	}

	int16_t getSyscallNo()
	{
		return syscall_id.getIntValue();
	}

	~SyscallTraceData()
	{
		reset();
	}
};


enum SyscallState
{
	ON_ENTER = 1,
	ON_EXIT = 2
};

struct ResourceTracer
{
	enum State
	{
		PENDING = 0,
		ACTIVE,
		CLOSED
	} m_state;

	uint64_t file_desc = 0;

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("res_tracer");

	virtual bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("ResourceTracer - onFilter : Not Implemented!");
		return false;
	};

	void setFileDescriptor(uint64_t fd)
	{
		file_desc = fd;
	}

	ResourceTracer &toActive()
	{
		m_state = ACTIVE;
		return *this;
	}

	ResourceTracer &toClosed()
	{
		m_state = CLOSED;
		return *this;
	}

	ResourceTracer &toPending()
	{
		m_state = PENDING;
		return *this;
	}
};

struct FileOperationTracer
{

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("res_tracer");

	virtual bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onFilter : Not Implemented!");
		return false;
	};

	virtual void onOpen(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onOpen : Not Implemented!");
	};
	virtual void onClose(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onClose : Not Implemented!");
	};
	virtual void onRead(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onRead : Not Implemented!");
	};
	virtual void onWrite(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onWrite : Not Implemented!");
	};
	virtual void onIoctl(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer - onIoctl : Not Implemented!");
	};
	virtual void onMmap(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer onMmap : Not Implemented!");
	};
	virtual void onMunmap(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer onMunmap : Not Implemented!");
	};
	virtual void onMisc(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("FileOperationTracer onMisc : Not Implemented!");
	};
};

struct NetworkOperationTracer
{

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("res_tracer");

	virtual bool onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer - onFilter : Not Implemented!");
		return false;
	};

	virtual void onClientOpen(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onClientOpen : Not Implemented!");
	};

	virtual void onClientClosed(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onClientClosed : Not Implemented!");
	};

	virtual void onOpen(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onOpen : Not Implemented!");
	};

	virtual void onClose(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onClose : Not Implemented!");
	};

	virtual void onRecv(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onRead : Not Implemented!");
	};

	virtual void onSend(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onWrite : Not Implemented!");
	};

	virtual void onIoctl(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onIoctl : Not Implemented!");
	};

	virtual void onConnect(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onConnect : Not Implemented!");
	};

	virtual void onBind(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onBind : Not Implemented!");
	};

	virtual void onAccept(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onAccept : Not Implemented!");
	};

	virtual void onListen(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onListen : Not Implemented!");
	};

	virtual void onMisc(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("NetworkOperationTracer onMisc : Not Implemented!");
	};
};

/// @brief Register syscall `onEnter` and `onExit` event of particular
/// syscall
struct SyscallHandler
{

	/// @brief Syscall which we want to intercept
	SysCallId m_syscall_id;

	/// @brief logging the data
	std::shared_ptr<spdlog::logger> m_log = spdlog::get("syscall");

	/// @brief Create the syscall object
	/// @param _syscall_id - syscall you want to intercept.
	SyscallHandler(SysCallId _syscall_id) : m_syscall_id(_syscall_id) {}

	~SyscallHandler() { m_syscall_id = SysCallId::NO_SYSCALL; }

	/// @brief This function is call before the Syscall data is passed to the Kernel
	/// @param sc_trace - system call data
	/// @return
	virtual int onEnter(SyscallTraceData &sc_trace) { return 0; };

	/// @brief This function is call after the Syscall data is executed by the Kernel
	/// @param sc_trace - this structure has the syscall parameter and return the value
	/// @return
	virtual int onExit(SyscallTraceData &sc_trace) { return 0; };
};

enum SysMngrResult
{
	ResultOk = 0,
	ErrorTooMany,
};

class SyscallManager
{

	/// @brief this arguments are preserved between syscall enter and syscall exit
	/// arguments should be filled on entry and cleared on exit, Ideal!
	SyscallTraceData m_cached_args;

	/// @brief maps syscall id to corresponding handler
	/// this data structure map multiple systemcall handler to same syscall id
	std::multimap<int16_t, SyscallHandler *> m_syscall_handler_map;

	/// @brief maps file descriptor to File operation class
	std::map<int, FileOperationTracer *> m_active_file_opts_handler;
	std::map<int, NetworkOperationTracer *> m_active_network_opts_handler;

	/// @brief file operations which are waiting to find its file descriptor
	std::list<FileOperationTracer *> m_pending_file_opts_handler;

	std::list<NetworkOperationTracer *> m_pending_network_opts_handler;

	std::map<pid_t, bool> m_pending_syscall;
	std::uintptr_t svc_inst_addr = 0;
	/// @brief logging data
	std::shared_ptr<spdlog::logger> m_log = spdlog::get("syscall");

	uint64_t m_syscall_executed = 0;

	void readSyscallParams(TraceeProgram &traceeProg);
	void readRetValue(TraceeProgram &traceeProg);

	int handleFileOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleNetworkOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleIPCOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleProcessOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleTimeOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);

	// void injectPendingSyscall(SyscallState sys_state,TraceeProgram& traceeProg);
public:
	int addFileOperationHandler(FileOperationTracer *file_opt_handler);
	int removeFileOperationHandler(FileOperationTracer *file_opt_handler);

	int addNetworkOperationHandler(NetworkOperationTracer *network_opt_handler);

	int addSyscallHandler(SyscallHandler *syscall_hdlr);
	int removeSyscallHandler(SyscallHandler *syscall_hdlr);

	/// @brief  This function is call before the Syscall data is passed to the Kernel
	/// @param traceeProg - tracee which is making the Syscall
	/// @return
	int onEnter(TraceeProgram &traceeProg);

	/// @brief This function is call after the Syscall data is executed by the Kernel
	/// @param traceeProg - tracee which is making the Syscall
	/// @return
	int onExit(TraceeProgram &traceeProg);

	// /// @brief Inject syscall in the running process
	// /// @return
	// int injectSyscall(std::unique_ptr<SyscallInject> syscall_data);
};

SysCallId amd64_canonicalize_syscall(AMD64_SYSCALL syscall_number);
SysCallId arm64_canonicalize_syscall(ARM64_SYSCALL syscall_number);

// this is because standard mapping is done on this syscall ID
SysCallId arm32_canonicalize_syscall(int16_t syscall_number);

SysCallId i386_canonicalize_syscall(int16_t syscall_number);

#endif