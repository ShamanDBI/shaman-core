// SPDX-License-Identifier: CC0-1.0+
#include <sys/syscall.h>
#include <sys/user.h>
#include <errno.h>
#include <sys/procfs.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ptrace.h>
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

#define PT_IF_CLONE(status) ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
#define PT_IF_FORK(status)  ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK  << 8)))
#define PT_IF_VFORK(status) ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
#define PT_IF_EXEC(status) ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
#define PT_IF_EXIT(status) ( status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))

enum TraceeState {
	WaitForInitialStop = 1,
	Running,
	Unknown
};

void PrintTraceeState(TraceeState st ){
	switch (st) {
		case TraceeState::WaitForInitialStop:
			cout << "INIT Stop";
			break;
		case TraceeState::Running:
			cout << "Running";
			break;
		case TraceeState::Unknown:
			cout << "Unknown";
			break;
	}
}


struct TraceeEvent {
	enum  {
		EXITED = 1, SIGNALED, STOPPED, CONTINUED, INVALID
	} state;

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
};


struct TrapReason {

	enum {
		CLONE = 1, // Process invoked `clone()`
		EXEC, // Process invoked `execve()`
		EXIT, // Process invoked `exit()`
		FORK, // Process invoked `fork()`
		VFORK, // Process invoked `vfork()`
		INVALID
	} status;

	pid_t pid;
};


TraceeEvent my_waitpid(pid_t pid) {
	TraceeEvent t_status;
    int child_status;
    int wait_ret = waitpid(pid, &child_status, WNOHANG | WCONTINUED);
    if (wait_ret == -1) {
        cout << "waitpid failed !" << endl;
    }
	t_status.state = TraceeEvent::INVALID;
	if (wait_ret == 0) {
		// this is no event for the child, exit no futher detail needed
		return t_status;
	}
	if (WIFSIGNALED(child_status)) {
		// cout << "WIFSIGNALED" << endl;
		t_status.state = TraceeEvent::SIGNALED;
		t_status.signaled.signal = WTERMSIG(child_status);
		t_status.signaled.dumped =  WCOREDUMP(child_status);
	} else if (WIFEXITED(child_status)) {
		// cout << "WIFEXITED" << endl;
		t_status.state = TraceeEvent::EXITED;
		t_status.exited.status = WEXITSTATUS(child_status);
	} else if (WIFSTOPPED(child_status)) {
		// cout << "WIFSTOPPED" << endl;
		t_status.state = TraceeEvent::STOPPED;
		t_status.stopped.signal = WSTOPSIG(child_status);
		t_status.stopped.status = child_status;
	} else if (WIFCONTINUED(child_status)) {
		// cout << "WIFCONTINUED" << endl;
		t_status.state = TraceeEvent::CONTINUED;
	} else {
		cout << "Unreachable Tracee state please handle it!" << endl;
		exit(-1);
	}
	return t_status;
}

void PrintTraceeStatus(TraceeEvent event) {
	cout << "TraceeStatus ";
	switch (event.state) {
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

class Debugger {

	int childPid;
	std::map<pid_t, TraceeState> tracees;

public:
	int spawn(const char * prog, char ** argv) {
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
		tracees.insert(make_pair(childPid, WaitForInitialStop));
	}

	int event_loop() {

		int child_status;
		printf("Waiting for Child to responded!\n");
		waitpid(childPid, &child_status, 0);
		printf("Child has responded!\n");
		// usr_gp_regs* gp_regs = (usr_gp_regs*)malloc(sizeof(usr_gp_regs));
		// sc_trace* gp_regs = (sc_trace*)malloc(sizeof(sc_trace));

		while (true) {
			ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
			do {
				cout << "cont" << endl;
				waitpid(childPid, &child_status, 0);

				if (WIFSIGNALED(child_status)) {
					printf("error: child killed by signal\n");
					return -1;
				}
				if (WIFEXITED(child_status)) {
					break;
				}

				if (!WIFSTOPPED(child_status) || !(WSTOPSIG(child_status) & 0x80)) {
					ptrace(PTRACE_SYSCALL, childPid, NULL, NULL);
				} else {
					break;
				}
			} while (true);

			if (WIFEXITED(child_status)) {
				cout << "Child exited" << endl;
				break;
			}

			// ptraceGetReg(childPid, &gPRegs);

		}

		return -1;
	}

	void ping_tracee_status() {
		cout << "Tracee state " << endl;
		for (auto i = tracees.begin(); i != tracees.end(); i++) {
			cout << "\tPID " << i->first << " , Status : ";
			PrintTraceeState(i->second);
			cout << endl;
		}
		cout << endl;
	}

	int event_loop2() {
		
		siginfo_t pt_sig_info = {0};
		TraceeState state;
		TraceeEvent event;

		while(!tracees.empty()) {
			cout << "------------------------------" << endl;
			pt_sig_info.si_pid = 0;	
			event.state = TraceeEvent::INVALID;
			ping_tracee_status();


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
			cout << "Sig Pid : " << pid_sig << endl;

			auto tracee_iter = tracees.find(pid_sig);
			if (tracee_iter != tracees.end()) {
				// tracee is found, its under over management
				state = tracee_iter->second;
			} else {
				cout<<"Tracee not found!\n" << endl;
				state = TraceeState::Unknown;
			}
			
			cout << "TS : " ;
			PrintTraceeState(state) ;
			cout << endl;

			if (state == TraceeState::Unknown) {
				cout << "Tracee is not under over management" << endl;
				// PrintTraceeStatus(my_waitpid(pid_sig));
				/*
				state = TraceeState::WaitForInitialStop;
				*/
				for (auto i = tracees.begin(); i != tracees.end(); i++) {
					pid_t tracee_pid = i->first;
					TraceeEvent ts_event = my_waitpid(tracee_pid);
					cout << "Inspecting PID " << i->first << " , Status : " << i->second << " ";
					PrintTraceeStatus(ts_event);
					cout << endl;
					if (ts_event.state != TraceeEvent::INVALID) {
						pid_sig = tracee_pid;
						event = ts_event;
						cout << "Proc PID : " << tracee_pid << " ";
						state = tracees[pid_sig];
						break;
					}
				}
			} else {
				event = my_waitpid(pid_sig);
			}
			PrintTraceeStatus(event); cout << endl;
			// cout << "Tracee Event : " << event.state << endl;


			pid_t new_pid = -1;
			TrapReason trap_reason = { TrapReason::INVALID, -1 };

			if(event.state == TraceeEvent::STOPPED && event.stopped.signal == SIGTRAP) {
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
					cout << "FORK" << endl;
					new_pid = 0;
					int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
					cout << "PT FORK : ret " << pt_ret << endl;
					trap_reason.status = TrapReason::FORK;
					trap_reason.pid = new_pid;
				} else if (PT_IF_VFORK(event.stopped.status)) {
					cout << "VFORK" << endl;
					new_pid = 0;
					// Get the PID of the new process
					int pt_ret = ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
					cout << "PT VFORK : ret " << pt_ret << endl;
					trap_reason.status = TrapReason::VFORK;
					trap_reason.pid = new_pid;
				} else {
					if(state != TraceeState::WaitForInitialStop) {
						cout << "Couldn't Find Why are we trapped! Need to handle this" << endl;
					}
				}
			}

			int ret = 0;
			switch(state) {
				case TraceeState::WaitForInitialStop:
					cout << "Initial Stop, prepaing the tracee!" << endl;
					ret = ptrace(PTRACE_SETOPTIONS, pid_sig, 0, 
						PTRACE_O_TRACECLONE |
						PTRACE_O_TRACEEXEC  |
						PTRACE_O_TRACEEXIT  |
						PTRACE_O_TRACEFORK  |
						PTRACE_O_TRACEVFORK
					);
					if (ret == -1) {
						cout << "Error occured while setting options" << endl;
					}
					ret = ptrace(PTRACE_CONT, pid_sig, 0L, 0L);
					if (ret == -1) {
						cout << "Error occured while continuee tracee" << endl;
					}

					// put the tracee in the running state
					tracees[pid_sig] = TraceeState::Running;
					break;
				case TraceeState::Running:
					cout << "Running" << endl;
					
					switch (event.state) {
						case TraceeEvent::EXITED:
							cout << "EXITED : process "<< pid_sig << " has exited!" << endl;
							tracees.erase(pid_sig);
							break;
						case TraceeEvent::SIGNALED:
							cout << "SIGNALLED : process" << pid_sig << " terminated by a signal!" << endl;
							tracees.erase(pid_sig);
						case TraceeEvent::STOPPED:
							cout << "STOPPED : ";
							if (trap_reason.status == TrapReason::CLONE ||
								trap_reason.status == TrapReason::FORK || 
								trap_reason.status == TrapReason::VFORK ) {
								if (trap_reason.pid == 0) {
									cout << "Whhaat tthhhee.... heelll...., child id cannot be zero! Not adding child to the list" << endl;
								} else {
									cout << "New child "<< trap_reason.pid << " is added to trace list!" << endl;
									tracees.insert(make_pair(trap_reason.pid, WaitForInitialStop));
								}
								ret = ptrace(PTRACE_CONT, pid_sig, 0L, 0L);
							} else if(trap_reason.status == TrapReason::EXEC || 
									trap_reason.status == TrapReason::EXIT ) {
								cout << "we have stopped for exec or exit!" << endl;
								ret = ptrace(PTRACE_CONT, pid_sig, 0L, 0L);
							} else {
								cout << "Not sure why we have stopped!" << endl;
								ret = ptrace(PTRACE_CONT, pid_sig, 0L, event.signaled.signal);
							}
							break;
						case TraceeEvent::CONTINUED:
							cout << "CONTINUED ";
							break;
						default:
							cout << "Unknown state" << event.state << endl;
							ret = ptrace(PTRACE_CONT, pid_sig, 0L, 0L);
					}
					
					break;
				default:
					cout << "Unknown Tracee State" << endl;
					break;
			}
		}
		cout << "There are not tracee left to debug. Exiting!" << endl;
	}
};

int main() {
	Debugger debug;
	// char* argument_list[] = {"echo", "Hello", "World", NULL};
	// debug.spawn("/bin/echo", argument_list);
	// debug.event_loop2();

	char* argument_listd[] = {"/local/mnt/workspace/pdev/ptrace-debugger/test/test_prog/prog", NULL};
	debug.spawn("/local/mnt/workspace/pdev/ptrace-debugger/test/test_prog/prog", argument_listd);
	debug.event_loop2();
	
	cout << "Good Bye!" << endl;
}