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

enum TraceeState {
	WaitForInitialStop = 1,
	Running
};


typedef struct  {
	enum  {
		EXITED, SIGNALED, STOPPED, CONTINUED,
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
} tracee_status_t;

tracee_status_t my_waitpid(pid_t pid) {
	tracee_status_t t_status;
    int child_status;
    int wait_ret = waitpid(pid, &child_status, WNOHANG | WCONTINUED);
    if (wait_ret == -1) {
        cout << "waitpid failed !" << endl;
    }

	if (WIFSIGNALED(child_status)) {
		t_status.state = tracee_status_t::SIGNALED;
		t_status.signaled.signal = WTERMSIG(child_status);
		t_status.signaled.dumped =  WCOREDUMP(child_status);
	} else if (WIFEXITED(child_status)) {
		t_status.state = tracee_status_t::EXITED;
		t_status.exited.status = WEXITSTATUS(child_status);
	} else if (WIFSTOPPED(child_status)) {
		t_status.state = tracee_status_t::STOPPED;
		t_status.stopped.signal = WSTOPSIG(child_status);
	} else if (WIFCONTINUED(child_status)) {
		t_status.state = tracee_status_t::CONTINUED;
	} else {
		cout << "Unreachable Tracee state please handle it!" << endl;
		exit(-1);
	}
	return t_status;
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

	int event_loop2() {
		siginfo_t pt_sig_info = {0};
		while(!tracees.empty()) {
			pt_sig_info.si_pid = 0;	
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
			cout << "Pid : " << pid_sig << endl;
			
			if (pid_sig == 0) {
				cout << "Special Case of waitid(), please handle it!" << endl;
				exit(-1);
			}
			tracee_status_t event = my_waitpid(pid_sig);

			pid_t new_pid = -1;
			
			if(event.state == tracee_status_t::STOPPED && event.signaled.signal == SIGTRAP) {
				cout << "SIGTRAP" << endl;
				if (status >> 16) == PTRACE_EVENT_CLONE {
					ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
				} else if (status >> 16) == PTRACE_EVENT_EXEC {
					cout << "Exec" << endl;
				} else if (status >> 16) == PTRACE_EVENT_EXIT {
					cout << "Exit" << endl;
				} else if (status >> 16) == PTRACE_EVENT_FORK {
					ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
				} else if (status >> 16) == PTRACE_EVENT_VFORK {
					// Get the PID of the new process
					let mut new_pid = 0;
					ptrace(PTRACE_GETEVENTMSG, pid_sig, 0, &new_pid);
				} else {
					cout << "Need to handle this" << endl;
				}
			}


		}
	}
};

int main() {
	Debugger debug;
	char* argument_list[] = {"echo", "Hello", "World", NULL};
	debug.spawn("/bin/echo", argument_list);
	debug.event_loop2();
	cout << "Exiting" << endl;
}