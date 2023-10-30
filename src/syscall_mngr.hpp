#ifndef H_SYSCALL_HANDLER_H
#define H_SYSCALL_HANDLER_H

#include <unordered_set>
#include <map>
#include <list>
#include <spdlog/spdlog.h>

#include "syscall.hpp"
#include "registers.hpp"
#include "memory.hpp"
#include "debug_opts.hpp"



/**
 * @brief dfd
 * 
 */
struct SyscallTraceData {
	pid_t m_pid;						/* If 0, this tcb is free */
	SysCallId syscall_id;					/* System call number */
	int64_t v_rval;						/* Return value */
	uint8_t nargs;						/* number of argument */
	uint64_t v_arg[SYSCALL_MAXARGS];	/* System call arguments */
	
	SyscallTraceData() {
		syscall_id = SysCallId::NO_SYSCALL;
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
	virtual bool onFilter(SyscallTraceData& sc_trace) {
		return true;
	};

	/**
	 * @brief callback on open file event
	 * 
	 */
	virtual void onOpen(SyscallState sys_state, SyscallTraceData& sc_trace) {
		m_log->error("FT : onOpen");
	};
	virtual void onClose(SyscallState sys_state, SyscallTraceData& sc_trace) {
		m_log->error("FT : onClose");
	};
	virtual void onRead(SyscallState sys_state, SyscallTraceData& sc_trace) {
		m_log->error("FT : onRead");
	};
	virtual void onWrite(SyscallState sys_state, SyscallTraceData& sc_trace) {
		m_log->error("FT : onWrite");
	};
	virtual void onIoctl(SyscallState sys_state, SyscallTraceData& sc_trace) {
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
};


struct SyscallHandler {

	SysCallId m_syscall_id;
	
	SyscallHandler(SysCallId _syscall_id): 
		m_syscall_id(_syscall_id) {}

	~SyscallHandler() {};

	virtual int onEnter(SyscallTraceData& sc_trace) { return 0; };

	virtual int onExit(SyscallTraceData& sc_trace) { return 0; };

};

template<class DebugOptsT>
class SyscallManager {
	
	// this system call which are related to filer operations
	std::unordered_set<SysCallId> file_ops_syscall_id{
		SysCallId::READ,
		SysCallId::WRITE,
		SysCallId::CLOSE,
		SysCallId::IOCTL
	};

	// this arguments are preserved between syscall enter and syscall exit
	// arguments should be filled on entry and cleared on exit, Ideal!
	SyscallTraceData m_cached_args;

	// SyscallEntry* m_syscall_info = nullptr;

	std::multimap<SysCallId, SyscallHandler*> m_syscall_handler_map;

	std::map<int, FileOperationTracer*> m_file_ops_handler;

	std::list<FileOperationTracer*> m_file_ops_pending;

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main_log");

public:

	void readSyscallParams(DebugOptsT* debug_opts);

	void readRetValue(DebugOptsT* debug_opts);

	int handleFileOpt(SyscallState sys_state, DebugOptsT* debug_opts);

	virtual int addFileOperationHandler(FileOperationTracer* file_opt_handler);
	virtual int removeFileOperationHandler(FileOperationTracer* file_opt_handler);

	virtual int addSyscallHandler(SyscallHandler* syscall_hdlr);
	virtual int removeSyscallHandler(SyscallHandler* syscall_hdlr);

	virtual int onEnter(DebugOptsT* debug_opts);

	virtual int onExit(DebugOptsT* debug_opts);

};

#endif