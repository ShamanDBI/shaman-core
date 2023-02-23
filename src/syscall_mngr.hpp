#ifndef H_SYSCALL_HANDLER_H
#define H_SYSCALL_HANDLER_H

#include "syscall.hpp"
#include "registers.hpp"
#include "memory.hpp"

class SyscallHandler {
	
	pid_t m_pid;
	// to get system call parameter
	Registers* m_register = nullptr;

	// to read tracee argument value
	RemoteMemory* m_traceeMemory = nullptr;

	// this arguments are preserved between syscall enter and syscall exit
	// arguments should be filled on entry and cleared on exit, Ideal!
	SyscallEntry* m_cached_args = nullptr;

public:

	SyscallHandler(pid_t tracee_pid): 
		m_pid(tracee_pid),
		m_traceeMemory(new RemoteMemory(tracee_pid)),
		m_register(new Registers(tracee_pid)) {}

	void readParameters();

	virtual int onEnter();

	virtual int onExit();

};

#endif