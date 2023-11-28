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


#define SYSCALL_ID_ARM32    7
#define SYSCALL_ARM32_ARG_0 0
#define SYSCALL_ARM32_ARG_1 1
#define SYSCALL_ARM32_ARG_2 2
#define SYSCALL_ARM32_ARG_3 3
#define SYSCALL_ARM32_ARG_4 4
#define SYSCALL_ARM32_ARG_5 5
#define SYSCALL_ARM32_ARG_6 6
#define SYSCALL_ARM32_RET   0


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


/**
 * @brief Get callback for all file related system call 
 *        the tracking id will be file descriptor
 * 
 */
struct FileOperationTracer {

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");
	
	/**
	 * @brief this function will let you filter the file
	 *        you want to trace, if you want to trace
	 *        all files the return true;
	 * @param debug_opts debugging related API access
	 * @param sc_trace system call parameter
	 * @return true if you want to track the file descriptor
	 * @return false if you want dont want to track the file descriptor
	 */
	virtual bool onFilter(DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		return true;
	};

	/**
	 * @brief callback on open file event
	 * 
	 */
	virtual void onOpen(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->error("FT : onOpen");
	};
	virtual void onClose(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->error("FT : onClose");
	};
	virtual void onRead(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->error("FT : onRead");
	};
	virtual void onWrite(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->error("FT : onWrite");
	};
	virtual void onIoctl(SyscallState sys_state, DebugOpts& debugOpts, SyscallTraceData& sc_trace) {
		m_log->error("FT : onIoctl");
	};
};


class SocketOperationTracer {

public:
	virtual void onOpen() = 0;
	virtual void onClose() = 0;
	virtual void onRead() = 0;
	virtual void onWrite() = 0;
	virtual void onIoctl() = 0;
	virtual void onBind() = 0;
	virtual void onListen() = 0;
};


struct SyscallHandler {

	SysCallId m_syscall_id;
	
	SyscallHandler(SysCallId _syscall_id): 
		m_syscall_id(_syscall_id) {}

	~SyscallHandler() {};

	virtual int onEnter(SyscallTraceData& sc_trace) { return 0; };
	virtual int onExit(SyscallTraceData& sc_trace) { return 0; };

};

class SyscallManager {
	
	// this system call which are related to filer operations
	std::unordered_set<int16_t> file_ops_syscall_id{
		SysCallId::READ,
		SysCallId::WRITE,
		SysCallId::CLOSE,
		SysCallId::IOCTL,
		SysCallId::STAT
	};

	// this arguments are preserved between syscall enter and syscall exit
	// arguments should be filled on entry and cleared on exit, Ideal!
	SyscallTraceData m_cached_args;

	// maps syscall id to corresponding handler
	// this data structure map multiple systemcall handler to same syscall id
	std::multimap<int16_t, SyscallHandler*> m_syscall_handler_map;

	// maps file descriptor to File operation class
	std::map<int, FileOperationTracer*> m_file_ops_handler;

	// file operations which are waiting to find its file descriptor
	std::list<FileOperationTracer*> m_file_ops_pending;

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

public:

	void readSyscallParams(TraceeProgram& traceeProg);
	void readRetValue(TraceeProgram& traceeProg);

	int handleFileOpt(SyscallState sys_state, DebugOpts& debug_opts);

	virtual int addFileOperationHandler(FileOperationTracer* file_opt_handler);
	virtual int removeFileOperationHandler(FileOperationTracer* file_opt_handler);

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