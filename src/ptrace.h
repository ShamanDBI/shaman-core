#include <sys/ptrace.h>
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

#ifndef _PTRACE_H
#define _PTRACE_H

#define MAX_KERNEL_ARGS 6
#define MAX_REGS 31

typedef struct _usr_gp_regs {
	union {
		struct user_regs_struct user_regs;
		struct {
			unsigned long regs[MAX_REGS];
			unsigned long sp;
			unsigned long pc;
			unsigned long pstate;
		};
	};
	int syscallno;
} usr_gp_regs, *ptr_usr_gp_regs;

// system call tracing data - specially designed to trace system call
typedef struct _sc_trace {
	uint64_t scno; // system call number
	uint64_t args[MAX_KERNEL_ARGS]; // system call argument
	uint64_t sc_ret ; // system call return value
} sc_trace, *ptr_sc_trace;


long ptraceGetReg(pid_t pid, struct user_regs_struct_full* regs);
long ptraceSetReg(pid_t pid, struct user_regs_struct_full* regs);

#endif