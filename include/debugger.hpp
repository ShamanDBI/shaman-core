#ifndef H_DEBUGGER_H
#define H_DEBUGGER_H

#include <iostream>
#include <tuple>
#include <queue>
#include <map>
#include <unistd.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
// #include <sys/cachectl.h>


#include "syscall_mngr.hpp"
#include "breakpoint_mngr.hpp"

#include "linux_debugger.hpp"

/**
 * 
 * Tracing a single process is easy you don't need to take care
 * of what breakpoint handle to invoke
 * ######################################################################
 * Fork Event
 * ----------
 * The fork call basically makes a duplicate of the current process,
 * identical in almost every way (not everything is copied over,
 * for example, resource limits in some implementations but the idea
 * is to create as close a copy as possible).
 * 
 * The new process (child) gets a different process ID (PID) and has
 * the PID of the old process (parent) as its parent PID (PPID).
 * Because the two processes are now running exactly the same code,
 * they can tell which is which by the return code of fork - the child
 * gets 0, the parent gets the PID of the child. This is all, of course,
 * assuming the fork call works - if not, no child is created and the
 * parent gets an error code.
 * 
 * How to handle this event?
 * -------------------------
 * 
 * Inform the breakpoint manager that new process has been added
 * so that it can add the current new process ID to all the active
 * breakpoint object
 * 
 * ######################################################################
 *  
 * Vfrok Event
 * -----------
 * The basic difference between vfork() and fork() is that when a new
 * process is created with vfork(), the parent process is temporarily
 * suspended, and the child process might borrow the parent's address
 * space. This strange state of affairs continues until the child process
 * either exits, or calls execve(), at which point the parent process
 * continues.
 * 
 * This means that the child process of a vfork() must be careful to
 * avoid unexpectedly modifying variables of the parent process. In
 * particular, the child process must not return from the function
 * containing the vfork() call, and it must not call exit() 
 * NOTE : if it needs to exit, it should use _exit(); actually, this
 * is also true for the child of a normal fork().
 * 
 * How to handle this event?
 * -------------------------
 * This system call is highly likely to be followed by *Exec* event
 * so this shold be chained with Exec even handler
 * 
 * ######################################################################
 * 
 * Exec Event
 * ----------
 * The exec call is a way to basically replace the entire current process
 * with a new program. It loads the program into the current process
 * space and runs it from the entry point. exec() replaces the current
 * process with a the executable pointed by the function. Control never
 * returns to the original program unless there is an exec() error.
 * 
 * How to handle this event?
 * -------------------------
 * 
 * The new process is completed different from the current tracee process
 * it would be good to hand over this new tracee to different debugger
 * instance
 * 
 * ######################################################################
 * 
 * Clone Event
 * clone(), as fork(), creates a new process. Unlike fork(), these calls
 * allow the child process to share parts of its execution context with the
 * calling process, such as the memory space, the table of file descriptors,
 * and the table of signal handlers.
 * 
 * When the child process is created with clone(), it executes the function
 * application fn(arg) (This differs from fork(), where execution continues
 * in the child from the point of the original fork() call.) The fn argument
 * is a pointer to a function that is called by the child process at the
 * beginning of its execution. The arg argument is passed to the fn function.
 * 
 * When the fn(arg) function application returns, the child process terminates.
 * The integer returned by fn is the exit code for the child process. The child
 * process may also terminate explicitly by calling exit(2) or after receiving
 * a fatal signal
 * 
 * Exit Event
 * ----------
 * 
 * Processs has exited all the resources data in the debugger has to be released
 * 
 * How to handle this event?
 * ----
 * 
 * Inform the breakpoint manger
 * 
 * Reference
 * ---------
 * Good Discussion about this topic can be found on this thread
 * https://stackoverflow.com/questions/4856255/the-difference-between-fork-vfork-exec-and-clone
 */

class TraceeProgram;
class TraceeFactory;
class SyscallInjector;

/**
 * @brief CPU Architectur of the Target
 * 
 */
enum CPU_ARCH : uint8_t {
	X86 = 0x00,
	AMD64 = 0x01,
	ARM32 = 0x10,
	ARM64 = 0x20
};

/**
 * @brief Execution mode of the Target
 * 
 */
enum CPU_MODE : uint8_t{
	x86_16 = 0x00,
	x86_32 = 0x01,
	x86_64 = 0x02,
	THUMB = 0x10,
	ARM = 0x11,
	ARM_64 = 0x12
};

/**
 * @brief All the Architecture speicfic detials will be avaible in this
 * class 
 */
struct TargetDescription {
	CPU_MODE m_cpu_mode;
	CPU_ARCH m_cpu_arch;
};

/**
 * @brief Callback for the events which Process can generate
 * 
 * @ingroup programming_interface
 */
class ProcessEvent {
	
	/// @brief called when new process is created
	virtual void onCreateProcess() = 0;

	/// @brief Thread has exited
	virtual void onThreadExit() = 0;

	/// @brief Proces has exited
	virtual void onExit() = 0;

	/// @brief Process just forked
	virtual void onFork() = 0;

	/// @brief new Module has been loaded in the process
	virtual void onModuleLoad() = 0;

	/// @brief Called when a Library is unloaded 
	virtual void onModuleUnload() = 0;
};


/// @brief Result while Attaching to a Process for debugging
enum class DebugResult {
	/// @brief Everything is OK!
	Success = 0,
	
	/// @brief Error while Creating Fork for Tracing
	ErrForking,

	/// @brief Error while attaching program for Debugging
	ErrAttachingPtrace,
	
	/// @brief error while exiting from exec family of function
	ErrExit,

	/// @brief Error while stopping the thread
	ErrStopThread,
};

/**
 * @brief The class provide the means to Debug the process.
 *  
 * This class provides a means by which one process (the "tracer") may observe 
 * and control the execution of another process (the "tracee"), and examine and
 * change the tracee's memory and registers. It is primarily used to implement
 * breakpoint debugging and system call tracing.
 */
class Debugger {

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("debugger");

	/// @brief Currently Active Tracee request which is been processed
	pid_t m_signalled_pid = 0;
	std::map<pid_t, TraceeProgram*> m_tracees;

public:
	
	BreakpointMngr* m_breakpointMngr = nullptr;
	SyscallManager* m_syscallMngr = nullptr;
	
	SyscallInjector* m_syscall_injector = nullptr;

	/// @brief Thread Group Leader process
	TraceeProgram* m_leader_tracee = nullptr;

	
	std::string* m_prog = nullptr;

	std::vector<std::string>* m_argv = nullptr;
	
	pid_t prev_pid = 0;

	TraceeFactory* m_tracee_factory = nullptr; //remove
 
	bool m_traceSyscall = false;

	bool m_followFork = false;

	TargetDescription& m_target_desc;

	Debugger& followFork() {
		m_followFork = true;
		return *this;
	};

	Debugger& traceSyscall() {
		m_traceSyscall = true;
		return *this;
	};

	Debugger(TargetDescription& _target_desc);

	/**
	 * @brief Create new Process attach to the debugger immediately
	 * 
	 * @param cmdline 
	 * @return DebugResult 
	 */
	DebugResult spawn(std::vector<std::string>& cmdline);

	/// @brief Attach to process and all the threads
	/// @param tracee_pid Process ID to attach to
	/// @return 
	DebugResult attach(pid_t tracee_pid);

	/// @brief Attach to single Thread
	/// @param tracee_pid 
	/// @return 
	DebugResult attachThread(pid_t tracee_pid);

	/// @brief Stop all the Threads which we control
	DebugResult stopAllThreads();
	
	/// @brief Stop the One Tracee Thread only
	/// @param stopTracee Tracee to stop
	DebugResult stopThread(TraceeProgram &stopTracee);

	/// @brief in and architecture CPU mode can change not its architecture
	/// for eg 64 bit machine can run 32 bit program but and ARM
	/// cannot natively run x64 binary
	void setCPUMode(CPU_MODE cpu_mode);

	TraceeProgram* addChildTracee(pid_t child_tracee_pid);

	void dropChildTracee(TraceeProgram* child_tracee);

	void printAllTraceesInfo();

	void getTrapReason(DebugEventPtr& debug_event, TraceeProgram* tracee_info);

	bool eventLoop();

	bool isBreakpointTrap(siginfo_t* tracee_pid);
	
	void parseBrk(std::vector<std::string>& brk_pnt_str);

	Debugger& setSyscallMngr(SyscallManager* sys_mngr) {
		m_syscallMngr = sys_mngr;
		return *this;
	};

	Debugger& setBreakpointMngr(BreakpointMngr* brk_mngr) {
		m_breakpointMngr = brk_mngr;
		return *this;
	};

	void addBreakpoint(std::vector<std::string>& _brk_pnt_str);

	TraceeProgram* getTracee(pid_t tracee_pid);
	/*
	void addPendingBrkPnt(std::vector<std::string>& brk_pnt_str) {
		for(auto brk_pnt: brk_pnt_str) {
			m_breakpointMngr->addModuleBrkPnt(brk_pnt);
		}
	}
	*/

	void addSyscallHandler(SyscallHandler* syscall_hdlr) {
		m_syscallMngr->addSyscallHandler(syscall_hdlr);
	};

	void addFileOperationHandler(FileOperationTracer* file_opts) {
		m_syscallMngr->addFileOperationHandler(file_opts);
	};

	void addNetworkOperationHandler(NetworkOperationTracer* network_opts) {
		m_syscallMngr->addNetworkOperationHandler(network_opts);
	};

	// void setBreakpoint(Breakpoint* breakpoint) {
	// };

};

#endif
