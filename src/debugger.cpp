#include <sys/syscall.h>
#include <sys/user.h>
#include <error.h>
#include <sys/procfs.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <iostream>
#include <map>
#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "memory.cpp"
#include "modules.cpp"


using namespace std;


// Taken from : https://gist.github.com/SBell6hf/77393dac37939a467caf8b241dc1676b

#define PT_IF_CLONE(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
#define PT_IF_FORK(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)))
#define PT_IF_VFORK(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define PT_IF_EXEC(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC  << 8)))
#define PT_IF_EXIT(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT  << 8)))
#define PT_IF_SYSCALL(signal) (signal == (SIGTRAP | 0x80))

#define CASE_SYSCALL(id, name) case id: spdlog::trace("syscall {} - {}", id, name); break;


void printSyscall(pid_t tracee_pid) {
	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;
	io.iov_len = sizeof(struct user_regs_struct);

	if (ptrace(PTRACE_GETREGSET, tracee_pid, (void*)NT_PRSTATUS, (void*)&io) == -1) {
		spdlog::error("Failed to get tracee register");
	}

	auto rem_mem = RemoteMemory(tracee_pid);
	// auto rem_file_path = new Addr(regs.rsi, 100);

	uint32_t syscall_id = regs.orig_rax;
	
	// Ref : https://filippo.io/linux-syscall-table/
	switch (syscall_id) {
		CASE_SYSCALL(0, "read")
		// case 257: {
		// 	cout << "openat : " ;
		// 	printf("RAX : %p\n", regs.rax);
		// 	printf("RSI : %p\n", regs.rsi);
		// 	printf("RDI : %p\n", regs.rdi);
		// 	printf("RDX : %p\n", regs.rdx);
		// 	printf("RCX : %p\n", regs.rcx);
		// 	printf("R8 : %p\n", regs.r8);
		// 	printf("R9 : %p\n", regs.r9);
		// 	auto rem_file_path = new Addr(regs.rsi, 100);
		// 	getchar();
		// 	rem_mem.read(rem_file_path, 100);
		// 	printf("path - %s \n", rem_file_path->addr);
		// 	delete rem_file_path;
		// 	getchar();
		// }
		CASE_SYSCALL(1, "write")
		CASE_SYSCALL(2, "open")
		CASE_SYSCALL(3, "close")
		CASE_SYSCALL(5, "fstat")
		CASE_SYSCALL(21, "access")
		CASE_SYSCALL(9, "mmap")
		CASE_SYSCALL(10, "mprotect")
		CASE_SYSCALL(11, "munmap")
		CASE_SYSCALL(12, "brk")
		CASE_SYSCALL(56, "clone")
		CASE_SYSCALL(57, "fork")
		CASE_SYSCALL(58, "vfork")
		CASE_SYSCALL(60, "exit")
		CASE_SYSCALL(231, "exit_group")
		// CASE_SYSCALL(257, "openat")
		default:
			cout << "Unknown " << endl;
			break;
	}
}

class TraceeInfo;

struct TraceeEvent {
	
	enum EventType {
		EXITED = 1, SIGNALED, STOPPED, CONTINUED, INVALID
	} type;

	union {
		struct  {
			uint32_t status;
		} exited;

		struct  {
			uint32_t signal;
			bool dumped;
		} signaled;
		
		struct  {
			uint32_t signal;
			uint32_t status;
		} stopped;
	};

	TraceeEvent(TraceeEvent::EventType et): type(et) {}
	TraceeEvent(): type(INVALID) {}
	
	bool isValidEvent() {
		return type != INVALID;
	}

	void setInvalid() {
		type = INVALID;
	}
};

struct TrapReason {

	enum {
		CLONE = 1, 	// Process invoked `clone()`
		EXEC, 		// Process invoked `execve()`
		EXIT, 		// Process invoked `exit()`
		FORK, 		// Process invoked `fork()`
		VFORK, 		// Process invoked `vfork()`
		SYSCALL,
		BREAKPOINT,
		INVALID
	} status;

	pid_t pid; // this holds value of new pid in case of clone/vfork/frok
};

class Debugger {

	std::map<pid_t, TraceeInfo*> m_Tracees;

public:

	int spawn(vector<string>& cmdline);

	void addChildTracee(pid_t child_tracee_pid);

	void dropChildTracee(TraceeInfo* child_tracee);

	void printAllTraceesInfo();

	TrapReason getTrapReason(TraceeEvent event, TraceeInfo* tracee_info);

	void eventLoop();

	bool isBreakpointTrap(siginfo_t* tracee_pid);

};


enum DebugType {
	DEFAULT        = (1 << 1),
	BREAKPOINT     = (1 << 2),
	FOLLOW_FORK    = (1 << 3),
	SYSCALL        = (1 << 4),
	SINGLE_STEP    = (1 << 5)
};

class TraceeInfo {

	// this is current state of the tracee
	enum TraceeState {
		// once the tracee is spawned it is assigned this state
		// tracee is then started with the desired ptrace options
		INITIAL_STOP = 1,
		// on the initialization is done it is set in the running
		// state
		RUNNING,
		// tracee is put in this state when it has sent request to
		// kernel and the kernel is processing system call, this 
		// mean syscall enter has already occured
		SYSCALL,
		// the process has existed and object is avaliable to free
		EXITED, 
		UNKNOWN
	} m_state ;

	DebugType debugType;	
	Debugger& m_debugger;
	RemoteMemory* m_TraceeMemory;

	std::map<uintptr_t, Breakpoint*> m_breakpoints;
	
	// this is brk point is saved to restore the breakpoint
	// once it has executed, if there is no breakpoint has 
	// hit then this value should be null
	Breakpoint * pendingBrkPt = nullptr;

public:
	pid_t m_pid; // tracee pid
	// TraceeEvent event; // this represnt current event of event loop
	
	~TraceeInfo () {
		delete m_TraceeMemory;
	}

	// this is used when new tracee is found
	TraceeInfo(pid_t tracee_pid, Debugger& debugger, DebugType debug_type):
		m_pid(tracee_pid), debugType(debug_type), 
		m_debugger(debugger), m_TraceeMemory(new RemoteMemory(tracee_pid)),
		m_state(TraceeState::INITIAL_STOP) {}
	
	TraceeInfo(pid_t tracee_pid, Debugger& debugger):
		m_pid(tracee_pid), debugType(DebugType::DEFAULT),
		m_debugger(debugger), m_TraceeMemory(new RemoteMemory(tracee_pid)),
		m_state(TraceeState::INITIAL_STOP) {}

	// returns true if the tracee is in valid state
	bool isValidState() {
		return m_state != TraceeState::UNKNOWN;
	}

	DebugType getChildDebugType() {
		if (debugType | DebugType::FOLLOW_FORK) {
			return debugType;
		} else {
			return DebugType::DEFAULT;
		}
	}

	bool isInitialized(){
		return m_state == INITIAL_STOP;
	}

	void toStateRunning() {
		m_state = TraceeState::RUNNING;
	}

	void toStateSysCall() {
		m_state = TraceeState::SYSCALL;
	}

	void toStateExited() {
		m_state = TraceeState::EXITED;
	}

	bool hasExited() {
		return m_state == TraceeState::EXITED;
	}

	int contExecution(uint32_t sig = 0) {
		// int debug_flag = 
		int pt_ret = -1;
		int mode = debugType | DebugType::DEFAULT;
		// cout << endl << " DEbug type " << debugType << " "<< DebugType::DEFAULT << "=" << mode << "PID " << pid << endl;
		if (debugType & DebugType::DEFAULT) {
			// cout << "contExec Tracee CONT" << endl;
			pt_ret = ptrace(PTRACE_CONT, m_pid, 0L, sig);
		} else if (debugType & DebugType::SYSCALL) {
			// cout << "contExec Tracee Syscall" << endl;
			pt_ret = ptrace(PTRACE_SYSCALL, m_pid, 0L, sig);
		} else if (debugType & DebugType::SINGLE_STEP) {
			pt_ret = ptrace(PTRACE_SINGLESTEP, m_pid, 0L, sig);
		}
		if(pt_ret < 0) {
			spdlog::error("ptrace continue call failed! Err code : {} ", pt_ret);
		}
		return pt_ret;
	}

	int singleStep() {
		int pt_ret = ptrace(PTRACE_SINGLESTEP, m_pid, 0L, 0);
		if(pt_ret < 0) {
			spdlog::error("failed to single step! Err code : {} ", pt_ret);
		}
	}

	string getStateString() {
		switch (m_state) {
			case TraceeState::INITIAL_STOP:
				return string("INIT Stop");
				break;
			case TraceeState::RUNNING:
				return string("RUNNING");
				break;
			case TraceeState::SYSCALL:
				return string("SYSCALL");
				break;
			case TraceeState::EXITED:
				return string("EXITED");
				break;
			case TraceeState::UNKNOWN:
				return string("UNKNOWN");
				break;
		};
	}

	void printStatus() {
		spdlog::debug("PID : {} State : {}", m_pid, getStateString());
	}

	void processPtraceEvent(TraceeEvent event, TrapReason trap_reason) {
		// this function processes "PTRACE_EVENT stops" event
		if (trap_reason.status == TrapReason::CLONE ||
			trap_reason.status == TrapReason::FORK || 
			trap_reason.status == TrapReason::VFORK ) {
			m_debugger.addChildTracee(trap_reason.pid);
			contExecution();
		} else if( trap_reason.status == TrapReason::EXEC) {
			contExecution();
		} else if( trap_reason.status == TrapReason::EXIT ) {
			// toStateExited();
			contExecution();
		} else if(trap_reason.status == TrapReason::SYSCALL) {
			// this state mean the tracee execution is handed to the
			// kernel for syscall process, 
			// NOTE: OS has not clear way to
			// distingish if the call is syscall enter or exit
			// and its debugger responsibity to track it
			contExecution();
		} else {
			spdlog::warn("Not sure why we have stopped!");
			contExecution(event.signaled.signal);
		}
	}

	Breakpoint* getBreakpointObj(intptr_t bk_addr) {
		auto brk_pnt_iter = m_breakpoints.find(bk_addr);
		if (brk_pnt_iter != m_breakpoints.end()) {
			// breakpoint is found, its under over management
			return brk_pnt_iter->second;
		} else {
			spdlog::warn("No Breakpoint object found! This is very unusual!");
			return nullptr;
		}

	}

	void setBreakpointAtAddr(intptr_t brk_addr, string& label) {
		Breakpoint* brk_pnt_obj = new Breakpoint(brk_addr, m_pid, label);
		brk_pnt_obj->enable();
		m_breakpoints.insert(make_pair(brk_addr, brk_pnt_obj));
	}

	void processState(TraceeEvent event, TrapReason trap_reason) {
		// restrict the changing of tracee state to this function only
		int ret = 0;
		string lb = "loop";
		// auto proc_map = new ProcessMap(m_pid);

		switch(m_state) {
			case UNKNOWN:
				 spdlog::critical("FATAL : You cannot possibily be living in this state");
				break;
			case INITIAL_STOP:
				spdlog::info("Initial Stop, prepaing the tracee!");
				ret = ptrace(PTRACE_SETOPTIONS, m_pid, 0, 
					PTRACE_O_TRACECLONE   |
					PTRACE_O_TRACEEXEC    |
					PTRACE_O_TRACEEXIT    |
					PTRACE_O_TRACEFORK    |
					PTRACE_O_TRACESYSGOOD |
					PTRACE_O_TRACEVFORK
				);

				if (ret == -1) {
					spdlog::error("Error occured while setting ptrace options while restarting the tracee!");
				}

				// setBreakpointAtAddr(0x555555555383, lb);
				toStateRunning();

				// TODO : figure out the lift time of this param
				// proc_map->parse();
				// proc_map->print();
				contExecution();
				break;
			case RUNNING:
				spdlog::debug("RUNNING");
				
				switch (event.type) {
					case TraceeEvent::EXITED:
						spdlog::info("EXITED : process {} has exited!", m_pid);
						toStateExited();
						break;
					case TraceeEvent::SIGNALED:
						spdlog::critical("SIGNALLED : process {} terminated by a signal!!", m_pid);
						toStateExited();
						break;
					case TraceeEvent::STOPPED:
						spdlog::info("STOPPED : ");
						if(trap_reason.status == TrapReason::SYSCALL) {
							toStateSysCall();
							spdlog::debug("SYSCALL ENTER");
							printSyscall(m_pid);
						} else if(trap_reason.status == TrapReason::BREAKPOINT) {
										
							if (pendingBrkPt != nullptr) {
								pendingBrkPt->enable();
								contExecution();
								pendingBrkPt = nullptr;
							} else {
								struct user_regs_struct* regs = m_TraceeMemory->getGPRegisters();
								// PC points to the next instruction after execution
								uintptr_t brk_addr = --regs->rip;
								spdlog::debug("Breakpoint Hit! addr 0x{:x}", brk_addr);
								// find the breakpoint object for further processing
								auto brk_obj = getBreakpointObj(brk_addr);
								pendingBrkPt = brk_obj;
								
								brk_obj->handle();

								// restore the value of original breakpoint instruction
								brk_obj->disable();
								// restreat back to the instruction which caused the
								// breakpoint trap
								m_TraceeMemory->setGPRegisters(regs);
								free(regs);
								// this is done to restore the breakpoint
								singleStep();
							}
							// contExecution();
							break;
						}
						processPtraceEvent(event, trap_reason);
						break;
					case TraceeEvent::CONTINUED:
						cout << "CONTINUED";
						contExecution();
						break;
					default:
						spdlog::error("ERROR : UNKNOWN state {}", event.type);
						contExecution();
				}
				break;
			case SYSCALL:
				/*
					DOCS :
					Syscall-enter-stop and syscall-exit-stop are indistinguishable
       				from each other by the tracer. The tracer needs to keep track of
       				the sequence of ptrace-stops in order to not misinterpret
       				syscall-enter-stop as syscall-exit-stop or vice versa. In
       				general, a syscall-enter-stop is always followed by syscall-exit-
       				stop, PTRACE_EVENT stop, or the tracee's death; no other kinds of
       				ptrace-stop can occur in between.

					thats the reason we have the process this again
				*/
				switch (event.type) {
					case TraceeEvent::EXITED:
						spdlog::info("SYSCALL : EXITED : process {} has exited!", m_pid);
						toStateExited();
						break;
					case TraceeEvent::SIGNALED:
						spdlog::critical("SYSCALL : SIGNALLED : process {} terminated by a signal!!", m_pid);
						toStateExited();
						break;
					case TraceeEvent::STOPPED:
						if(trap_reason.status == TrapReason::SYSCALL) {
							spdlog::info("SYSCALL : EXIT");
							// change the state once we have process the event
							toStateRunning();
						}
						processPtraceEvent(event, trap_reason);
						break;
					default:
						spdlog::error("SYSCALL : ERROR : UNKNOWN state {}", event.type);
						contExecution();
				}
				break;
			default:
				spdlog::error("FATAL : Undefined Tracee State", event.type);
				break;
		}
	}

};


// this is used in case of ARM64
struct user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};


TraceeEvent my_waitpid(pid_t pid) {
	TraceeEvent t_status;
    int child_status;
    int wait_ret = waitpid(pid, &child_status, WNOHANG | WCONTINUED);
    if (wait_ret == -1) {
        cout << "waitpid failed !" << endl;
    }
	t_status.type = TraceeEvent::INVALID;
	if (wait_ret == 0) {
		// this is no event for the child, exit no futher detail needed
		return t_status;
	}
	if (WIFSIGNALED(child_status)) {
		// cout << "WIFSIGNALED" << endl;
		t_status.type = TraceeEvent::SIGNALED;
		t_status.signaled.signal = WTERMSIG(child_status);
		t_status.signaled.dumped =  WCOREDUMP(child_status);
	} else if (WIFEXITED(child_status)) {
		// cout << "WIFEXITED" << endl;
		t_status.type = TraceeEvent::EXITED;
		t_status.exited.status = WEXITSTATUS(child_status);
	} else if (WIFSTOPPED(child_status)) {
		// cout << "WIFSTOPPED" << endl;
		t_status.type = TraceeEvent::STOPPED;
		t_status.stopped.signal = WSTOPSIG(child_status);
		t_status.stopped.status = child_status;
	} else if (WIFCONTINUED(child_status)) {
		// cout << "WIFCONTINUED" << endl;
		t_status.type = TraceeEvent::CONTINUED;
	} else {
		cout << "Unreachable Tracee state please handle it!" << endl;
		exit(-1);
	}
	return t_status;
}

void PrintTraceeStatus(TraceeEvent event) {
	cout << "TraceeStatus ";
	switch (event.type) {
		case TraceeEvent::EXITED :
			cout << "EXITED : " << event.exited.status << " ";
			break;
		case TraceeEvent::SIGNALED:
			cout << "SIGNALED : " << event.signaled.signal << " ";
			break;
		case TraceeEvent::STOPPED:
			cout << "STOPPED : signal " << event.stopped.signal << " " << event.stopped.status;
			break;
		case TraceeEvent::CONTINUED:
			cout << "CONTINUED ";
			break;
		case TraceeEvent::INVALID:
			cout << "INVALID ";
			break;
	}

}


int Debugger::spawn(vector<string>& cmdline) {

	
	// covert cmdline arguments to exev parameter type
	std::vector<const char *> args;
	
	args.reserve(cmdline.size() + 1);
	for(const auto& sp: cmdline) {
		args.push_back(sp.c_str());
	}
	// needed to terminate the args list
	args.push_back(nullptr);

	pid_t childPid = fork();
	
	if (childPid == -1) {
		spdlog::error("fork() for tracee failed failed!");
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			return -1;
		}
		
		int status_code = execvp(args[0], const_cast<char* const *>(args.data()));

		if (status_code == -1) {
			spdlog::error("Process did not terminate correctly\n");
			exit(1);
		}

		spdlog::debug("This line will not be printed if execvp() runs correctly\n");

		return 0;
	}

	spdlog::debug("New Child spawed! PID : {}", childPid);
	
	m_Tracees.insert(make_pair(childPid, new TraceeInfo(childPid, *this, DebugType::DEFAULT)));
}

void Debugger::addChildTracee(pid_t child_tracee_pid) {
	if (child_tracee_pid == 0) {
		spdlog::critical("FATAL : Whhaat tthhhee.... heelll...., child id cannot be zero! Not adding child to the list");
	} else {
		spdlog::debug("New child {} is added to trace list!", child_tracee_pid);
		m_Tracees.insert(make_pair(child_tracee_pid, new TraceeInfo(child_tracee_pid, *this)));
	}
}

void Debugger::dropChildTracee(TraceeInfo* child_tracee) {
	spdlog::debug("Dropping child tracee PID : {}", child_tracee->m_pid);
	m_Tracees.erase(child_tracee->m_pid);
	delete child_tracee;
	// child_tracee = nullptr;
}

void Debugger::printAllTraceesInfo() {
	spdlog::debug("Tracee state : ");
	TraceeInfo *tc_info = nullptr;
	for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
		// spdlog::debug("ID : {}", i->first);
		tc_info = i->second;
		tc_info->printStatus();
	}
	cout << endl;
}

bool Debugger::isBreakpointTrap(siginfo_t* info) {
	spdlog::debug("BK test signal code : {}", info->si_code);

	switch (info->si_code) {
	//one of these will be set if a breakpoint was hit
	case SI_KERNEL:
		spdlog::debug("Breakpoint TRAP : KERNEL");
	case TRAP_BRKPT:
		spdlog::debug("Breakpoint TRAP : Software");
		return true;
	case TRAP_TRACE:
		//this will be set if the signal was sent by single stepping
		spdlog::debug("Breakpoint : TRAP_TRACE, possibly due to single stepping!");
		return true;
	default:
		spdlog::warn("Unknown SIGTRAP code {}", info->si_code);
	}
	return false;
}

TrapReason Debugger::getTrapReason(TraceeEvent event, TraceeInfo* tracee_info) {
	pid_t new_pid = -1;
	pid_t pid_sig = tracee_info->m_pid;

	TrapReason trap_reason = { TrapReason::INVALID, -1 };

	if(event.type == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
		if (PT_IF_CLONE(event.stopped.status)) {
			spdlog::debug("SIGTRAP : CLONE");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			// spdlog::debug("SIGTRAP : PT CLONE : ret {}");
			trap_reason.status = TrapReason::CLONE;
			trap_reason.pid = new_pid;
		} else if (PT_IF_EXEC(event.stopped.status)) {
			spdlog::debug("SIGTRAP : Exec");
			trap_reason.status = TrapReason::EXEC;
			trap_reason.pid = -1;
		} else if (PT_IF_EXIT(event.stopped.status)) {
			spdlog::debug("SIGTRAP : Exit");
			trap_reason.status = TrapReason::EXIT;
			trap_reason.pid = -1;
		} else if (PT_IF_FORK(event.stopped.status)) {
			spdlog::debug("SIGTRAP : Fork");
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::FORK;
			trap_reason.pid = new_pid;
		} else if (PT_IF_VFORK(event.stopped.status)) {
			spdlog::debug("SIGTRAP : VFork");
			new_pid = 0;
			// Get the PID of the new process
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::VFORK;
			trap_reason.pid = new_pid;
		} else {
			if(!tracee_info->isInitialized()) {
				siginfo_t sig_info;
				ptrace(PTRACE_GETSIGINFO, pid_sig, nullptr, &sig_info);
				if (isBreakpointTrap(&sig_info)) {
					spdlog::debug("SIGTRAP : Breakpoint was hit !");
					trap_reason.status = TrapReason::BREAKPOINT;
				} else {
					spdlog::warn("SIGTRAP : Couldn't Find Why are we trapped! Need to handle this!");
				}
			}
		}
	} else if (event.type == TraceeEvent::STOPPED && PT_IF_SYSCALL(event.stopped.signal)) {
		spdlog::debug("SIGTRAP : SYSCALL");
		trap_reason.status = TrapReason::SYSCALL;
	} else if (event.type == TraceeEvent::STOPPED) {
		spdlog::warn("This STOP Signal not understood by us!");
	}
	return trap_reason;
}

void Debugger::eventLoop() {
		
	siginfo_t pt_sig_info = {0};
	// TraceeState state;
	TraceeEvent event;
	// TraceeInfo invalid_tracee TraceeInfo(*this);
	TraceeInfo *traceeInfo;
	TraceeEvent invalid_event = TraceeEvent();

	while(!m_Tracees.empty()) {
		spdlog::debug("------------------------------");
		pt_sig_info.si_pid = 0;	
		traceeInfo = nullptr;
		event = invalid_event;

		printAllTraceesInfo();

		int ret_wait = waitid(
			P_ALL, 0, 
			&pt_sig_info,
			WEXITED | WSTOPPED | WCONTINUED | WNOWAIT
		);

		if (ret_wait == -1) {
			spdlog::critical("waitid failed!");
			exit(-1);
		}
		
		pid_t pid_sig = pt_sig_info.si_pid;
		if (pid_sig == 0) {
			spdlog::warn("Special Case of waitid(), please handle it!");
			exit(-1);
		}

		spdlog::info("Signaled Pid : {} Signal Code : {}", pid_sig, pt_sig_info.si_code);

		auto tracee_iter = m_Tracees.find(pid_sig);
		if (tracee_iter != m_Tracees.end()) {
			// tracee is found, its under over management
			traceeInfo = tracee_iter->second;
		} else {
			spdlog::info("Tracee not found!");
			traceeInfo = nullptr;
		}
		
		// cout << "TS : " ;
		// PrintTraceeState(state);
		// cout << endl;

		if (traceeInfo == nullptr) {
			spdlog::info("Tracee is not under over management");
			// reset the current processed tracee info
			event = invalid_event;
			pid_sig = -1;
			bool found_event = false;
			for (auto i = m_Tracees.begin(); i != m_Tracees.end(); i++) {
				pid_t tracee_pid = i->first;
				TraceeEvent ts_event = my_waitpid(tracee_pid);
				traceeInfo = i->second;
				spdlog::debug("Inspecting ");
				traceeInfo->printStatus();
				PrintTraceeStatus(ts_event);
				// cout << endl;
				if (ts_event.isValidEvent()) {
					found_event = true;
					spdlog::debug("Event from PID : {}", tracee_pid);
					pid_sig = tracee_pid;
					traceeInfo = m_Tracees[pid_sig];
					event = ts_event;
					break;
				}
			}
			if(!found_event) {
				spdlog::critical("No tracee with event found! This should not happend, handle it!");
			}
		} else {
			event = my_waitpid(pid_sig);
		}

		// spdlog::debug("EL "; PrintTraceeStatus(event); cout << endl;
		// cout << "Tracee Event : " << event.type << endl;
		if (traceeInfo) {
			TrapReason trap_reason = getTrapReason(event, traceeInfo);
			traceeInfo->processState(event, trap_reason);
			if (traceeInfo->hasExited()) {
				dropChildTracee(traceeInfo);				
			}
		}
		// processTraceeState(tracee_info, trap_reason);
	}
	spdlog::info("There are not tracee left to debug. Exiting!");
}


int main(int argc, char **argv) {

    CLI::App app{"Shaman DBI Framework"};
	
	string trace_log_path, app_log_path;
	pid_t attach_pid {-1};
	std::vector<string> exec_prog;
	std::vector<uintptr_t> brk_pnt_addrs;
	

    app.add_option("-l,--log", app_log_path, "application debug logs");
	app.add_option("-o,--trace", trace_log_path, "output of the tracee logs");
	app.add_option("-p,--pid", attach_pid, "PID of process to attach to");
	app.add_option("-b,--brk", brk_pnt_addrs, "Address of the breakpoints");
	// app.add_option("-f,--follow", brk_pnt_addrs, "follow the fork/clone/vfork syscalls");
	// app.add_option("-s,--syscall", brk_pnt_addrs, "trace system calls");
	app.add_option("-e,--exec", exec_prog, "program to execute")->expected(-1);

    CLI11_PARSE(app, argc, argv);
	
    spdlog::info("Welcome to Shaman!");
	spdlog::set_level(spdlog::level::debug); // Set global log level to debug

	
	Debugger debug;
	debug.spawn(exec_prog);
	debug.eventLoop();
	
	spdlog::debug("Good Bye!");
}
