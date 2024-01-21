#ifndef H_TRACEE_H
#define H_TRACEE_H

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "syscall_mngr.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "breakpoint_mngr.hpp"
#include "linux_debugger.hpp"
#include "registers.hpp"
#include "debugger.hpp"
#include "syscall_injector.hpp"
#include "breakpoint.hpp"

class TargetDescription;


enum DebugType {
	DEFAULT        = (1 << 1),
	BREAKPOINT     = (1 << 2),
	FOLLOW_FORK    = (1 << 3),
	TRACE_SYSCALL  = (1 << 4),
	SINGLE_STEP    = (1 << 5),
	FOLLOW_OPTS    = (1 << 6)
};

/// @brief this is current state of the tracee
enum TraceeState {

	/// @brief once the tracee is spawned it is assigned this state
	// tracee is then started with the desired ptrace options
	INITIAL_STOP = 1,
	
	/// @brief We are trying to attach to a running process
	ATTACH,
	
	/// @brief once the initialization is done it is set in the running
	/// state
	RUNNING,
	
	/// @brief tracee is put in this state when it has sent request to
	/// kernel and the kernel is processing system call, this 
	/// mean syscall enter has already occured
	IN_SYSCALL,

	/// @brief syscall injection in progress
	INJECT_SYSCALL,
	
	/// @brief the process has existed and object is avaliable to free
	EXITED, 

	/// @brief there is hit for a breakpoint and the tracee is in the
	/// process of step over.
	BREAKPOINT_HIT,

	/// @brief Tracee was stoppe explicitly
	STOPPED,
	
	/// @brief Invalid state, not to be used anywhere! Use to indicate
	/// error
	UNKNOWN
};


struct TraceeProgram {

	TraceeState m_state;

	// pid of the process which is getting traced
	pid_t m_pid;

	// thread groud id, which is the pid of the parent thread
	pid_t m_tg_pid;

	// Debugger* m_debugger;
	DebugOpts& m_debug_opts;
	// SyscallManager* m_syscallMngr = nullptr;

  	bool m_followFork = false;

	// syscall call been injected in the tracee
	std::unique_ptr<SyscallInject> m_inject_call;

  	std::shared_ptr<spdlog::logger> m_log = spdlog::get("tracee");

	DebugType debugType;

	// Breakpoint which is currently handling
	uintptr_t m_brkpnt_addr;

	// when the breakpoint is hit it has to be single-stepped
	// and restored. This is handled by state transition 
	// This variable stores the active breakpoint in the 
	// state-transition
	Breakpoint* m_active_brkpnt = nullptr;

	// this is a temprory breapoint to handle single-step during
	// breakpoint handling
	std::unique_ptr<BranchData> m_single_step_brkpnt = nullptr;

	TargetDescription &m_target_desc;
	// BreakpointMngr* m_breakpointMngr;

	/// @brief pid of the program we are tracing/debugging
	pid_t pid() {
		return m_pid;
	}

	/// @brief Get thread group id
	/// @return 
	pid_t tid() {
		return m_tg_pid;
	};
	
	~TraceeProgram () {
		// spdlog::warn("TraceeProgram : going out of scope!");
		m_pid = 0;
		m_tg_pid = 0;
	}

	TraceeProgram(pid_t _tracee_pid, DebugType debug_type,
		DebugOpts& _debug_opts, TargetDescription& _target_desc):
		m_state(TraceeState::INITIAL_STOP), debugType(debug_type),
		m_pid(_tracee_pid), m_tg_pid(_tracee_pid),
		m_debug_opts(_debug_opts), m_target_desc(_target_desc) {}

	// TraceeProgram& setDebugOpts(const DebugOpts& debug_opts) {
	// 	m_debug_opts = debug_opts;
	// 	return *this;
	// };

	DebugOpts& getDebugOpts() {
		return m_debug_opts;
	};

	TraceeProgram& setPid(pid_t tracee_pid) {
		m_pid = tracee_pid;
		m_debug_opts.setPid(tracee_pid);
		return *this;
	};

	TraceeProgram& setThreadGroupid(pid_t thread_group_pid) {
		m_tg_pid = thread_group_pid;
		return *this;
	};

	TraceeProgram& setLogFile(std::string log_name) {
		auto log_file_name = spdlog::fmt_lib::format("{}_{}.log", log_name, pid());
		auto log_inst_name = spdlog::fmt_lib::format("tc-{}",pid());
		m_log = spdlog::basic_logger_mt(log_inst_name, log_file_name);
		return *this;
	};

	TraceeProgram& followFork() {
		m_followFork = true;
		return *this;
	}

	bool isValidState();

	DebugType getChildDebugType();

	bool isInitialized();

	void toAttach();

	void toStateRunning();

	void toStateSysCall();

	void toStateExited();

	void toStateInject();

	void toStateBreakpoint();

	bool hasExited();

	int contExecution(uint32_t sig = 0);

	int singleStep();

	std::string getStateString();

	void printStatus();

	// void addPendingBrkPnt(std::vector<std::string>& brk_pnt_str);
	
};


class TargetDescription;

class TraceeFactory {

	std::list<TraceeProgram *> m_cached_tracee;

public:
	
	// this function fills the cache with dummy tracees
	// this will reduce the creation time
	// void createDummyTracee();

	TraceeProgram* createTracee(pid_t tracee_pid, DebugType debug_type,
		TargetDescription& target_desc);

	void releaseTracee(TraceeProgram* tracee_obj);
};

#endif