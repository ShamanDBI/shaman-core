#include "ptrace.h"

using namespace std;

#ifdef __aarch64__

#define SYSCALL_CALLNO(regss) ((const int)(regss.syscallno))
#define SYSCALL_RETED(regss) (regss.regs[7] == 1 && SYSCALL_CALLNO(regss) != NO_SYSCALL)
#define SYSCALL_RETURN(regss) (regss.regs[0])
#define SYSCALL_ARG0(regss) (regss.regs[0])
#define SYSCALL_ARG1(regss) (regss.regs[1])
#define SYSCALL_ARG2(regss) (regss.regs[2])
#define SYSCALL_ARG3(regss) (regss.regs[3])
#define SYSCALL_ARG4(regss) (regss.regs[4])
#define SYSCALL_ARG5(regss) (regss.regs[5])
#define SYSCALL_SETCALLNO(regss, callNo) (regss.regs[8] = regss.syscallno = callNo)

long ptraceGetReg(pid_t pid, usr_gp_regs* regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (usr_gp_regs),
	};
	long err;
	if (err = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov)) {
		return err;
	} else {
		iov.iov_base += sizeof (struct user_regs_struct);
		iov.iov_len = sizeof (int);
		return ptrace(PTRACE_GETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
	}
}
long ptraceSetReg(pid_t pid, usr_gp_regs* regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (usr_gp_regs),
	};
	long err;
	if (err = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov)) {
		return err;
	} else {
		iov.iov_base += sizeof (struct user_regs_struct);
		iov.iov_len = sizeof (int);
		return ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov);
	}
}

#elif defined __x86_64__

#define SYSCALL_CALLNO(regss) ((const int)(regss.orig_rax))
#define SYSCALL_RETED(regss) (regss.rax != -38)
#define SYSCALL_RETURN(regss) (regss.rax)
#define SYSCALL_ARG0(regss) (regss.rdi)
#define SYSCALL_ARG1(regss) (regss.rsi)
#define SYSCALL_ARG2(regss) (regss.rdx)
#define SYSCALL_ARG3(regss) (regss.r10)
#define SYSCALL_ARG4(regss) (regss.r8)
#define SYSCALL_ARG5(regss) (regss.r9)
#define SYSCALL_SETCALLNO(regss, callNo) (regss.orig_rax = callNo)

long ptraceGetReg(pid_t pid, usr_gp_regs* regs) {
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof (usr_gp_regs),
	};
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}
/*
long ptraceGetSyscallArgs(pid_t pid, sc_trace* sc_args) {
    usr_gp_regs regs;
	struct iovec iov = {
		.iov_base = &regs,
		.iov_len = sizeof (usr_gp_regs),
	};
	int pret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    
    sc_args->scno = SYSCALL_CALLNO(regs);
    sc_args->args[0] = SYSCALL_ARG0(regs);
    sc_args->args[1] = SYSCALL_ARG1(regs);
    sc_args->args[2] = SYSCALL_ARG2(regs);
    sc_args->args[3] = SYSCALL_ARG3(regs);
    sc_args->args[4] = SYSCALL_ARG4(regs);
    sc_args->args[5] = SYSCALL_ARG5(regs);\
    sc_args->sc_ret = -1;
}
*/

#else

#error "Unsupported architecture. Currently only arm64 and x86_64 are supported."

#endif

