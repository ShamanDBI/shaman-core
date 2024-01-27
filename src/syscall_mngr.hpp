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

/**
 * @brief Captures the System Call parameters and the return value
 * 
 * @ingroup platform_support programming_interface
 */
struct SyscallTraceData
{
	/// @brief Process which is make this syscall 
	/// If 0, this syscall trace data is Invalid
	pid_t m_pid;

	/// @brief System call number which is converted to canonical System Call
	SysCallId syscall_id;

	/// @brief syscall number observer by the Register
	int16_t orig_syscall_number;
	
	/// @brief return value of the system call
	int64_t v_rval;

	/// @brief number of argument this syscall takes
	uint8_t nargs; 
	
	/// @brief argument of the syscall
	uint64_t v_arg[SYSCALL_MAXARGS];

	SyscallTraceData()
	{
		reset();
	}

	/// @brief Reset the object values to invalid state
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

	/// @brief Get integer value of the System Call number
	/// @return Integer value of Syscall Number
	int16_t getSyscallNo()
	{
		return syscall_id.getIntValue();
	}

	~SyscallTraceData()
	{
		reset();
	}
};

/**
 * @brief Result from System Call Interface
 * 
 */
enum class SyscallResult {
	/// @brief Continue the execution of the Syscall without changing anything
	Continue = 0,

	/// @brief We want to *Block* from the System Call from executing
	/// this can be done only at @ref SyscallHandler::onEnter function
	BlockSyscall,
};

/**
 * @brief System Call state value
 * 
 */
enum SyscallState
{
	/// @brief System call is just submitted to the Kernel, not yet exeucted
	ON_ENTER = 1,

	/// @brief System calls is executed by the Kernel, return value of the
	/// can be inspected
	ON_EXIT = 2
};

/// @brief Result while tracing the Result 
enum ResourceTraceResult {
	/// @brief Trace this File Descriptor and remove the class from watch list
	TRACE_ONLY = 1,

	/// @brief Trace the current File Descriptor and keep watching other Resource,
	TRACE_AND_KEEP,

	/// @brief We are not interested in Tracing this File Descriptor
	DONOT_TRACE,

	/// @brief Block the Syscall, this is usually intented to emulate the syscall
	/// and provide the fake data to be filled in the Parameter
	BLOCK_SYSCALL,

	/// @brief Continue the syscall execution normally
	CONTINUE,

	/// @brief Detach the Resource from Tracing this File Descriptor
	DETACH,
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

	virtual ResourceTraceResult onFilter(DebugOpts &debugOpts, SyscallTraceData &sc_trace)
	{
		m_log->warn("ResourceTracer - onFilter : Not Implemented!");
		return ResourceTraceResult::DONOT_TRACE;
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

/**
 * @addtogroup programming_interface
 * @{
 */

/**
 * @brief Callback Interface for Tracing File related Operation
 * 
 */
struct FileOperationTracer
{

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("res_tracer");

	/**
	 * @brief This Function will be Called everytime File is Created or opening an existing file,
	 * 
	 * This function gives a peek at the Syscall Data and you can implement logic 
	 * 
	 * @param debugOpts Tracee Making this System Call
	 * @param sc_trace System Call Parameter
	 * @return true Trace the file descriptor
	 * @return false Donot Trace the file descriptor
	 */
	virtual bool onFilter(DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onFilter : Not Implemented!");
		return false;
	};

	virtual void onOpen(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onOpen : Not Implemented!");
	};

	virtual void onClose(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onClose : Not Implemented!");
	};

	virtual void onRead(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onRead : Not Implemented!");
	};

	virtual void onSeek(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onSeek : Not Implemented!");
	};

	virtual void onWrite(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onWrite : Not Implemented!");
	};
	
	virtual void onStats(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onStats : Not Implemented!");
	};

	virtual void onIoctl(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer - onIoctl : Not Implemented!");
	};

	virtual void onMmap(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer onMmap : Not Implemented!");
	};
	
	virtual void onMunmap(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer onMunmap : Not Implemented!");
	};
	
	virtual void onMisc(SyscallState sys_state, DebugOpts &debugOpts, SyscallTraceData &scData)
	{
		m_log->warn("FileOperationTracer onMisc : Not Implemented!");
	};
};

/**
 * @brief Callback Interface for Tracing Network Related Operation
 * 
 */
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


/**
 * @brief Interface to Observe or change the System Call parameter
 * 
 * Register syscall @ref onEnter and @ref onExit event of particular syscall
 */
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

	/**
	 * @brief This function is call before the Syscall Data is passed to the Kernel
	 * for execution, You can change of the call parameter at this point.
	 * 
	 * @param sc_trace System call data
	 * @return int 
	 */
	virtual int onEnter(SyscallTraceData &sc_trace) { return 0; };

	/**
	 * @brief This function is call after the Syscall data is executed by the Kernel
	 * You can observe the return value of the Syscall at this state.
	 * 
	 * @param sc_trace this structure has the syscall parameter and return the value
	 * in @ref SyscallTraceData::v_rval
	 * @return int 
	 */
	virtual int onExit(SyscallTraceData &sc_trace) { return 0; };
};

/** @} End of group*/

/**
 * @brief Provides mean to register Syscall and Resource Tracing Interfaces 
 * 
 * @ingroup platform_support
 */
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

	/**
	 * @brief Read System Call parameter
	 * 
	 * @param traceeProg Tracee from which the call parameter will be read
	 * 
	 * @ingroup platform_support
	 */
	void readSyscallParams(TraceeProgram &traceeProg);
	
	/**
	 * @brief Read return value for the Registers
	 * 
	 * @param traceeProg Tracee from which the return value will be read
	 * 
	 * @ingroup platform_support
	 */
	void readRetValue(TraceeProgram &traceeProg);

	int handleFileOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleNetworkOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);

	/*
	int handleIPCOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleProcessOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	int handleTimeOperation(SyscallState sys_state, DebugOpts &debug_opts, SyscallTraceData &m_cached_args);
	*/

	// void injectPendingSyscall(SyscallState sys_state,TraceeProgram& traceeProg);
public:

	/**
	 * @brief Add File Operation for Tracing
	 * 
	 * @param file_opt_handler 
	 * @return int Number File Tracer currently registered
	 */
	int addFileOperationHandler(FileOperationTracer *file_opt_handler);

	// int removeFileOperationHandler(FileOperationTracer *file_opt_handler);
	
	/**
	 * @brief Add Network Tracing Interface
	 * 
	 * @param network_opt_handler 
	 * @return int 
	 */
	int addNetworkOperationHandler(NetworkOperationTracer *network_opt_handler);

	/**
	 * @brief Register interface for Tracing Individual Syscall Call
	 * 
	 * @param syscall_hdlr callback implemenation
	 * @return int 
	 */
	int addSyscallHandler(SyscallHandler *syscall_hdlr);

	// int removeSyscallHandler(SyscallHandler *syscall_hdlr);

	/**
	 * @brief This function is call before the Syscall data is passed to the Kernel
	 * 
	 * @param traceeProg tracee which is making the Syscall
	 * @return int 
	 */
	int onEnter(TraceeProgram &traceeProg);

	/**
	 * @brief This function is call before the Syscall data is passed to the Kernel
	 * 
	 * @param traceeProg tracee which is making the Syscall
	 * @return int 
	 */
	int onExit(TraceeProgram &traceeProg);
};

/**
 * @brief Following functions convert platform Specific System Call number to 
 * Platfrom independ canonical Syscall number
 * 
 * @param syscall_number 
 * @return SysCallId 
 */

SysCallId amd64_canonicalize_syscall(AMD64_SYSCALL syscall_number);
SysCallId arm64_canonicalize_syscall(ARM64_SYSCALL syscall_number);
SysCallId arm32_canonicalize_syscall(int16_t syscall_number);
SysCallId i386_canonicalize_syscall(int16_t syscall_number);

#endif