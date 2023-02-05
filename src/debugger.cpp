// SPDX-License-Identifier: CC0-1.0+
#include <sys/syscall.h>
#include <sys/user.h>
#include <errno.h>
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

#include "ptrace.h"
using namespace std;

#define NO_SYSCALL (-1)

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#ifndef MAP_ANON
#define MAP_ANON 0x20
#endif
#endif

// Taken from : https://gist.github.com/SBell6hf/77393dac37939a467caf8b241dc1676b

#define PT_IF_CLONE(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
#define PT_IF_FORK(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)))
#define PT_IF_VFORK(status)   ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define PT_IF_EXEC(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC  << 8)))
#define PT_IF_EXIT(status)    ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT  << 8)))
#define PT_IF_SYSCALL(signal) (signal == (SIGTRAP | 0x80))

#define CASE_SYSCALL(id, name) case id: cout << name << endl; break;

void printSyscall(pid_t tracee_pid) {
	struct iovec io;
	struct user_regs_struct regs;
	io.iov_base = &regs;
	io.iov_len = sizeof(struct user_regs_struct);

	if (ptrace(PTRACE_GETREGSET, tracee_pid, (void*)NT_PRSTATUS, (void*)&io) == -1) {
		cout << "ERROR : enable to get tracee register" << endl;
	}
	
	uint32_t syscall_id = regs.orig_rax;
	cout << "Syscall ID : " << syscall_id << " name : ";
	// Ref : https://filippo.io/linux-syscall-table/
	switch (syscall_id) {
		CASE_SYSCALL(0, "read")
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
		CASE_SYSCALL(257, "openat")
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
		CLONE = 1, // Process invoked `clone()`
		EXEC, // Process invoked `execve()`
		EXIT, // Process invoked `exit()`
		FORK, // Process invoked `fork()`
		VFORK, // Process invoked `vfork()`
		SYSCALL,
		BREAKPOINT,
		INVALID
	} status;

	pid_t pid; // this holds value of new pid in case of clone/vfork/frok
};

class Debugger {

	int childPid;
	std::map<pid_t, TraceeInfo*> tracees;

public:

	int spawn(const char * prog, char ** argv);

	void addChildTracee(pid_t child_tracee_pid);

	void dropChildTracee(pid_t child_tracee_pid);

	void printAllTraceesInfo();

	TrapReason getTrapReason(TraceeEvent event, TraceeInfo* tracee_info);

	void eventLoop();

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
		UNKNOWN
	} state ;

	DebugType debugType;	
	Debugger& debugger;
public:
	pid_t pid; // tracee pid
	// TraceeEvent event; // this represnt current event of event loop

	// this is used when new tracee is found
	TraceeInfo(pid_t tracee_id, Debugger& debugger, DebugType debug_type): \
		pid(tracee_id), debugType(debug_type), \
		debugger(debugger), \
		state(TraceeState::INITIAL_STOP) {}
	
	TraceeInfo(pid_t tracee_id, Debugger& debugger): \
		pid(tracee_id), debugType(DebugType::DEFAULT), \
		debugger(debugger), \
		state(TraceeState::INITIAL_STOP) {}

	// Default constructor initializes all the invalid state/value
	TraceeInfo(Debugger& debugger): \
		pid(-1), debugType(DebugType::DEFAULT), \
		debugger(debugger), \
		state(TraceeState::UNKNOWN) {}

	// returns true if the tracee is in valid state
	bool isValidState() {
		return state != TraceeState::UNKNOWN;
	}

	DebugType getChildDebugType() {
		if (debugType | DebugType::FOLLOW_FORK) {
			return debugType;
		} else {
			return DebugType::DEFAULT;
		}
	}

	void toStateRunning() {
		state = TraceeState::RUNNING;
	}

	void toStateSysCall() {
		state = TraceeState::SYSCALL;
	}

	int contExecution(uint32_t sig) {
		// int debug_flag = 
		int pt_ret = -1;
		int mode = debugType | DebugType::DEFAULT;
		// cout << endl << " DEbug type " << debugType << " "<< DebugType::DEFAULT << "=" << mode << "PID " << pid << endl;
		if (debugType & DebugType::DEFAULT) {
			// cout << "contExec Tracee CONT" << endl;
			pt_ret = ptrace(PTRACE_CONT, pid, 0L, sig);
		} else if (debugType & DebugType::SYSCALL) {
			// cout << "contExec Tracee Syscall" << endl;
			pt_ret = ptrace(PTRACE_SYSCALL, pid, 0L, sig);
		} else if (debugType & DebugType::SINGLE_STEP) {
			pt_ret = ptrace(PTRACE_SINGLESTEP, pid, 0L, sig);
		}
		if(pt_ret < 0) {
			cout << "ERROR : ptrace continue call failed! Err code : " << pt_ret << endl;
		}
		return pt_ret;
	}

	void printStatus() {
		cout << "PID : " << pid << " State : ";
		switch (state) {
			case TraceeState::INITIAL_STOP:
				cout << "INIT Stop";
				break;
			case TraceeState::RUNNING:
				cout << "RUNNING";
				break;
			case TraceeState::SYSCALL:
				cout << "SYSCALL";
				break;
			case TraceeState::UNKNOWN:
				cout << "UNKNOWN";
				break;
		};
		cout << endl;
	}

	void processPtraceEvent(TraceeEvent event, TrapReason trap_reason) {
		// this function processes "PTRACE_EVENT stops" event
		if (trap_reason.status == TrapReason::CLONE ||
			trap_reason.status == TrapReason::FORK || 
			trap_reason.status == TrapReason::VFORK ) {
			debugger.addChildTracee(trap_reason.pid);
			contExecution(0);
		} else if( trap_reason.status == TrapReason::EXEC || 
					trap_reason.status == TrapReason::EXIT ) {
			cout << endl;
			contExecution(0);
		} else if(trap_reason.status == TrapReason::SYSCALL) {
			// this state mean the tracee execution is handed to the
			// kernel for syscall process, 
			// NOTE: OS has not clear way to
			// distingish if the call is syscall enter or exit
			// and its debugger responsibity to track it
			contExecution(0);
		} else {
			cout << "Not sure why we have stopped!" << endl;
			contExecution(event.signaled.signal);
		}
	}

	void processState(TraceeEvent event, TrapReason trap_reason) {
		// restrict the changing of tracee state to this function only
		int ret = 0;
		pid_t pid_sig = pid;

		switch(state) {
			case UNKNOWN:
				cout << "FATAL : You cannot possibily be living in this state" << endl;
				break;
			case INITIAL_STOP:
				cout << "Initial Stop, prepaing the tracee!" << endl;
				ret = ptrace(PTRACE_SETOPTIONS, pid_sig, 0, 
					PTRACE_O_TRACECLONE   |
					PTRACE_O_TRACEEXEC    |
					PTRACE_O_TRACEEXIT    |
					PTRACE_O_TRACEFORK    |
					PTRACE_O_TRACESYSGOOD |
					PTRACE_O_TRACEVFORK
				);
				if (ret == -1) {
					cout << "Error occured while setting options" << endl;
				}
				// ret = ptrace(PTRACE_CONT, pid_sig, 0L, 0L);
				// ret = ptrace(PTRACE_SYSCALL , pid_sig, 0L, 0L);
				contExecution(0);
				if (ret == -1) {
					cout << "Error occured while continuee tracee" << endl;
				}
				// put the tracee in the RUNNING state
				// tracees[pid_sig] = RUNNING;
				toStateRunning();
				break;
			case RUNNING:
				cout << "RUNNING" << endl;
				
				switch (event.type) {
					case TraceeEvent::EXITED:
						cout << "EXITED : process "<< pid_sig << " has exited!" << endl;
						debugger.dropChildTracee(pid_sig);
						break;
					case TraceeEvent::SIGNALED:
						cout << "SIGNALLED : process" << pid_sig << " terminated by a signal!" << endl;
						debugger.dropChildTracee(pid_sig);
						break;
					case TraceeEvent::STOPPED:
						cout << "STOPPED : ";
						if(trap_reason.status == TrapReason::SYSCALL) {
							toStateSysCall();
							cout << "SYSCALL ENTER" << endl;
							printSyscall(pid);
						}
						processPtraceEvent(event, trap_reason);
						break;
					case TraceeEvent::CONTINUED:
						cout << "CONTINUED";
						contExecution(0);
						break;
					default:
						cout << "ERROR : UNKNOWN state" << event.type << endl;
						contExecution(0);
				}
				break;
			case SYSCALL:
				cout << "SYSCALL : ";
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
						cout << "EXITED : process "<< pid_sig << " has exited!" << endl;
						// TODO:
						// 	this is like cutting the branch you are setting on
						// 	you are deleting yourself, figure out a better way
						//  of handle this
						debugger.dropChildTracee(pid_sig);
						break;
					case TraceeEvent::SIGNALED:
						cout << "SIGNALLED : process" << pid_sig << " terminated by a signal!" << endl;
						// TODO:
						// 	this is like cutting the branch you are setting on
						// 	you are deleting yourself, figure out a better way
						//  of handle this
						debugger.dropChildTracee(pid_sig);
						break;
					case TraceeEvent::STOPPED:
						if(trap_reason.status == TrapReason::SYSCALL) {
							cout << "EXIT" << endl;
							// change the state once we have process the event
							toStateRunning();
						}
						processPtraceEvent(event, trap_reason);
						break;
					default:
						cout << "ERROR : UNKNOWN state" << event.type << endl;
						contExecution(0);
				}
				break;
			default:
				cout << "FATAL : Undefined Tracee State" << endl;
				break;
		}
	}

	bool isInitialized(){
		return state != INITIAL_STOP;
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


int Debugger::spawn(const char * prog, char ** argv) {
	childPid = fork();
	if (childPid == -1) {
		printf("error: fork() failed\n");
		return -1;
	}

	if (childPid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
			return -1;
		}
		int status_code = execvp(prog, argv);

		if (status_code == -1) {
			printf("Process did not terminate correctly\n");
			exit(1);
		}

		printf("This line will not be printed if execvp() runs correctly\n");

		return 0;
		execle("./test", "", NULL, NULL);
		return -1;
	}
	cout << "New Child spawed! PID : " << childPid << endl;
	
	tracees.insert(make_pair(childPid, new TraceeInfo(childPid, *this, DebugType::SYSCALL)));
}

void Debugger::addChildTracee(pid_t child_tracee_pid) {
	if (child_tracee_pid == 0) {
		cout << "FATAL : Whhaat tthhhee.... heelll...., child id cannot be zero! Not adding child to the list" << endl;
	} else {
		cout << "New child "<< child_tracee_pid << " is added to trace list!" << endl;
		tracees.insert(make_pair(child_tracee_pid, new TraceeInfo(child_tracee_pid, *this, DebugType::SYSCALL)));
	}
}

void Debugger::dropChildTracee(pid_t child_tracee_pid) {
	tracees.erase(child_tracee_pid);
}

void Debugger::printAllTraceesInfo() {
	cout << "Tracee state " << endl;
	TraceeInfo *tc_info = NULL;
	for (auto i = tracees.begin(); i != tracees.end(); i++) {
		cout << "ID : " << i->first << " ";
		tc_info = i->second;
		tc_info->printStatus();
	}
	cout << endl;
}

TrapReason Debugger::getTrapReason(TraceeEvent event, TraceeInfo* tracee_info) {
	pid_t new_pid = -1;
	pid_t pid_sig = tracee_info->pid;

	TrapReason trap_reason = { TrapReason::INVALID, -1 };

	if(event.type == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
		cout << "SIGTRAP : ";
		if (PT_IF_CLONE(event.stopped.status)) {
			cout << "CLONE" << endl;
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			cout << "PT CLONE : ret " << pt_ret << endl;
			trap_reason.status = TrapReason::CLONE;
			trap_reason.pid = new_pid;
		} else if (PT_IF_EXEC(event.stopped.status)) {
			cout << "Exec" << endl;
			trap_reason.status = TrapReason::EXEC;
			trap_reason.pid = -1;
		} else if (PT_IF_EXIT(event.stopped.status)) {
			cout << "Exit" << endl;
			trap_reason.status = TrapReason::EXIT;
			trap_reason.pid = -1;
		} else if (PT_IF_FORK(event.stopped.status)) {
			cout << "Fork" << endl;
			new_pid = 0;
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::FORK;
			trap_reason.pid = new_pid;
		} else if (PT_IF_VFORK(event.stopped.status)) {
			cout << "VFork" << endl;
			new_pid = 0;
			// Get the PID of the new process
			int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
			trap_reason.status = TrapReason::VFORK;
			trap_reason.pid = new_pid;
		} else {
			if(tracee_info->isInitialized()) {
				cout << "Couldn't Find Why are we trapped! Need to handle this" << endl;
			}
		}
	} else if (event.type == TraceeEvent::STOPPED && PT_IF_SYSCALL(event.stopped.signal)) {
		cout << "SIGTRAP : SYSCALL" << endl;
		trap_reason.status = TrapReason::SYSCALL;
	} else if (event.type == TraceeEvent::STOPPED) {
		cout << "This STOP Signal not understood by us!" << endl;
	}
	return trap_reason;
}

void Debugger::eventLoop() {
		
	siginfo_t pt_sig_info = {0};
	// TraceeState state;
	TraceeEvent event;
	// TraceeInfo invalid_tracee TraceeInfo(*this);
	TraceeInfo *tracee_info;
	TraceeEvent invalid_event = TraceeEvent();

	while(!tracees.empty()) {
		cout << "------------------------------" << endl;
		pt_sig_info.si_pid = 0;	
		tracee_info = NULL;
		event = invalid_event;

		printAllTraceesInfo();

		int ret_wait = waitid(
			P_ALL, 0, 
			&pt_sig_info,
			WEXITED | WSTOPPED | WCONTINUED | WNOWAIT
		);

		if (ret_wait == -1) {
			cout << "waitid failed!" << endl;
			exit(-1);
		}
		
		pid_t pid_sig = pt_sig_info.si_pid;
		if (pid_sig == 0) {
			cout << "Special Case of waitid(), please handle it!" << endl;
			exit(-1);
		}
		cout << "Signaled Pid : " << pid_sig << endl;

		auto tracee_iter = tracees.find(pid_sig);
		if (tracee_iter != tracees.end()) {
			// tracee is found, its under over management
			tracee_info = tracee_iter->second;
		} else {
			cout<<"Tracee not found!\n" << endl;
			tracee_info = NULL;
		}
		
		// cout << "TS : " ;
		// PrintTraceeState(state);
		// cout << endl;

		if (tracee_info == NULL) {
			cout << "Tracee is not under over management" << endl;
			// reset the current processed tracee info
			event = invalid_event;
			pid_sig = -1;
			bool found_event = false;
			for (auto i = tracees.begin(); i != tracees.end(); i++) {
				pid_t tracee_pid = i->first;
				TraceeEvent ts_event = my_waitpid(tracee_pid);
				tracee_info = i->second;
				cout << "Inspecting ";
				tracee_info->printStatus();
				PrintTraceeStatus(ts_event);
				cout << endl;
				if (ts_event.isValidEvent()) {
					found_event = true;
					cout << "Event from PID : " << tracee_pid << endl;
					pid_sig = tracee_pid;
					tracee_info = tracees[pid_sig];
					event = ts_event;
					break;
				}
			}
			if(!found_event) {
				cout << "ERROR : no tracee with event found! This should not happend, handle it!" << endl;
			}
		} else {
			event = my_waitpid(pid_sig);
		}

		cout << "EL "; PrintTraceeStatus(event); cout << endl;
		// cout << "Tracee Event : " << event.type << endl;
		if (tracee_info) {
			TrapReason trap_reason = getTrapReason(event, tracee_info);
			tracee_info->processState(event, trap_reason);
		}
		// processTraceeState(tracee_info, trap_reason);
	}
	cout << "There are not tracee left to debug. Exiting!" << endl;
}


int main() {
	Debugger debug;
	// char* argument_list[] = {"echo", "Hello", "World", NULL};
	// debug.spawn("/bin/echo", argument_list);
	// debug.event_loop2();

	char* argument_listd[] = {"/local/mnt/workspace/pdev/ptrace-debugger/test/test_prog/prog", "2", NULL};
	debug.spawn("/local/mnt/workspace/pdev/ptrace-debugger/test/test_prog/prog", argument_listd);
	debug.eventLoop();
	
	cout << "Good Bye!" << endl;
}