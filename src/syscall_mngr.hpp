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

struct SyscallTraceData {
	pid_t m_pid;						/* If 0, this syscall trace data is free */
	SysCallId syscall_id;				/* System call number */
	int64_t v_rval;						/* Return value */
	uint8_t nargs;						/* number of argument */
	uint64_t v_arg[SYSCALL_MAXARGS];	/* System call arguments */
	
	SyscallTraceData() {
		syscall_id = SysCallId::NO_SYSCALL;
	};

	int16_t getSyscallNo() {
		return syscall_id.getIntValue();
	};

	~SyscallTraceData() {
		syscall_id = SysCallId::NO_SYSCALL;
	};
};


enum SyscallState {
	ON_ENTER = 1,
	ON_EXIT = 2
};


struct ResourceTracer {
	enum State {
		PENDING = 0,
		ACTIVE,
		CLOSED
	} m_state;
	
	uint64_t file_desc = 0;

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
	
	virtual bool onFilter(DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("ResourceTracer - onFilter : Not Implemented!");
		return false;
	};

	void setFileDescriptor(uint64_t fd) {
		file_desc = fd;
	}
	
	ResourceTracer& toActive() {
		m_state = ACTIVE;
		return *this;
	}

	ResourceTracer& toClosed() {
		m_state = CLOSED;
		return *this;
	}

	ResourceTracer& toPending() {
		m_state = PENDING;
		return *this;
	}

};

struct FileOperationTracer {

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

	virtual bool onFilter(DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onFilter : Not Implemented!");
		return false;
	};

	virtual void onOpen(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onOpen : Not Implemented!");
	};
	virtual void onClose(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onClose : Not Implemented!");
	};
	virtual void onRead(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onRead : Not Implemented!");
	};
	virtual void onWrite(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onWrite : Not Implemented!");
	};
	virtual void onIoctl(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer - onIoctl : Not Implemented!");
	};
	virtual void onMisc(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("FileOperationTracer onMisc : Not Implemented!");
	};
};


struct NetworkOperationTracer {

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

	virtual bool onFilter(DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer - onFilter : Not Implemented!");
		return false;
	};
	
	virtual void onClientOpen(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onClientOpen : Not Implemented!");
	};

	virtual void onClientClosed(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onClientClosed : Not Implemented!");
	};

	virtual void onOpen(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onOpen : Not Implemented!");
	};

	virtual void onClose(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onClose : Not Implemented!");
	};

	virtual void onRecv(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onRead : Not Implemented!");
	};

	virtual void onSend(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onWrite : Not Implemented!");
	};

	virtual void onIoctl(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onIoctl : Not Implemented!");
	};

	virtual void onConnect(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onConnect : Not Implemented!");
	};
	
	virtual void onBind(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onBind : Not Implemented!");
	};

	virtual void onAccept(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onAccept : Not Implemented!");
	};

	virtual void onListen(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onListen : Not Implemented!");
	};

	virtual void onMisc(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->warn("NetworkOperationTracer onMisc : Not Implemented!");
	};

};


struct SyscallHandler {

	SysCallId m_syscall_id;
	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
	
	SyscallHandler(SysCallId _syscall_id): 
		m_syscall_id(_syscall_id) {}

	~SyscallHandler() {};

	virtual int onEnter(SyscallTraceData& sc_trace) { return 0; };
	virtual int onExit(SyscallTraceData& sc_trace) { return 0; };

};


class SyscallManager {
	
	// this arguments are preserved between syscall enter and syscall exit
	// arguments should be filled on entry and cleared on exit, Ideal!
	SyscallTraceData m_cached_args;

	// maps syscall id to corresponding handler
	// this data structure map multiple systemcall handler to same syscall id
	std::multimap<int16_t, SyscallHandler*> m_syscall_handler_map;

	// maps file descriptor to File operation class
	std::map<int, FileOperationTracer*> m_active_file_opts_handler;
	std::map<int, NetworkOperationTracer*> m_active_network_opts_handler;

	// file operations which are waiting to find its file descriptor
	std::list<FileOperationTracer*> m_pending_file_opts_handler;
	std::list<NetworkOperationTracer*> m_pending_network_opts_handler;

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");


	void readSyscallParams(TraceeProgram& traceeProg);
	void readRetValue(TraceeProgram& traceeProg);

	int handleFileOperation(SyscallState sys_state, DebugOpts& debug_opts, SyscallTraceData& m_cached_args);
	int handleNetworkOperation(SyscallState sys_state, DebugOpts& debug_opts, SyscallTraceData& m_cached_args);
	int handleIPCOperation(SyscallState sys_state, DebugOpts& debug_opts);
	int handleProessOperation(SyscallState sys_state, DebugOpts& debug_opts);
	int handleTimeOperation(SyscallState sys_state, DebugOpts& debug_opts);

public:

	virtual int addFileOperationHandler(FileOperationTracer* file_opt_handler);
	virtual int removeFileOperationHandler(FileOperationTracer* file_opt_handler);

	virtual int addNetworkOperationHandler(NetworkOperationTracer* network_opt_handler);

	virtual int addSyscallHandler(SyscallHandler* syscall_hdlr);
	virtual int removeSyscallHandler(SyscallHandler* syscall_hdlr);

	virtual int onEnter(TraceeProgram& traceeProg);
	virtual int onExit(TraceeProgram& traceeProg);

	// inject syscall

};

SysCallId amd64_canonicalize_syscall(AMD64_SYSCALL syscall_number);
SysCallId arm64_canonicalize_syscall(ARM64_SYSCALL syscall_number);

// this is because standard mapping is done on this syscall ID
SysCallId arm32_canonicalize_syscall(int16_t syscall_number);

SysCallId i386_canonicalize_syscall(int16_t syscall_number);

#endif