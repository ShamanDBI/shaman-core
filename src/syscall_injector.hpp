#ifndef H_SYSCALL_INJECTOR_H
#define H_SYSCALL_INJECTOR_H

#include "breakpoint.hpp"

/// @brief Parameter of the syscall you want to inject
/// The programming model needs more clarity who would you go
struct SyscallInject
{

	/// @brief General Purpose register copy
	std::uintptr_t m_gp_register_copy;

	/// @brief syscall number to inject
	uint64_t m_syscall_id;

	/// @brief argument of the system call
	uint64_t m_sys_args[SYSCALL_MAXARGS];

	/// @brief return value of the system call
	uint64_t m_ret_value;

	SyscallInject(uint64_t _syscall_id) : m_syscall_id(_syscall_id)
	{
		memset(m_sys_args, 0, sizeof(m_sys_args));
		m_ret_value = 0;
		m_gp_register_copy = 0;
	}

	~SyscallInject()
	{
		if (m_gp_register_copy)
		{
			free(reinterpret_cast<void *>(m_gp_register_copy));
			m_gp_register_copy = 0;
		}
	}

	SyscallInject &setSyscallId(uint64_t syscall_id)
	{
		m_syscall_id = syscall_id;
		return *this;
	}

	/// @brief Set the argument of the syscall you want to make
	/// @param arg_id index of the argument you want to set
	/// @param arg_value value of the argument value
	/// @return
	SyscallInject &setCallArg(int8_t arg_id, uint64_t arg_value)
	{
		m_sys_args[arg_id] = arg_value;
		return *this;
	}

	/// @brief this callback is called once the call inject is completed
	virtual void onComplete(){};
};

/**
 * @brief Algorithm used to inject syscall into the process
 *
 * 1. Put a breakpoint at which we want to inject syscall into the process
 *    this is done by `setUp` functionreak
 * 2. That breakpoint handler will then inject the syscall instruction and
 * 	  set the egister with the syscall parameter and backup the original
 * 	  register state of the program at that point.
 *    this is done by `execute` function
 * 3. After syscall is executed and on `INJECT_SYSCALL` handling event
 *    the original state of the register is restored with the PC value
 * 	  before the syscall instruction.
 *    this is done in `clearUp` function.
 * 
 * This model of programming allow for more flexibility interms of at
 * what point do you want to invoke a set of syscalls.
 * 
 * You could have different set of syscalls invoked at different point
 * of the program.
 */
struct SyscallInjector
{

    std::shared_ptr<spdlog::logger> m_log = spdlog::get("main");

	BreakpointPtr m_setup_breakpoint;

	/// @brief pending system call to inject
	std::list<std::unique_ptr<SyscallInject>> m_pending_syscall_inject;

	uint64_t m_syscall_inject_count = 0;

	/// @brief Queue the syscall parameter to inject
	/// @return
	void injectSyscall(std::unique_ptr<SyscallInject> syscall_data);

	/// @brief  Execute the syscall injection procedure
	/// @param sys_state state of the syscall
	/// @param traceeProg Tracee program you want inject the call
	void execute(TraceeProgram &traceeProg);

	/// @brief Setup the location all which the injection algorithm will execute
	/// @param _breakpoint_addr - location of the trigger
	/// @param traceeProg
	BreakpointPtr setUp(std::string& mod_name, std::uintptr_t _breakpoint_addr);

	/// @brief clean up breakpoint mess created to exeucte the algorithm
	///        and restore the process execution state
	/// @param traceeProg
	void cleanUp(TraceeProgram &traceeProg);
};

/// @brief Breakpoint to faciliate syscall injection
class SyscallInjectorBreakpoint : public Breakpoint
{
	SyscallInjector& m_syscall_inject;

public:
	SyscallInjectorBreakpoint(std::string &mod_name, std::uintptr_t bkpt_offset,
							  SyscallInjector& _sys_inject)
		: m_syscall_inject(_sys_inject),
		  Breakpoint(mod_name, bkpt_offset, SINGLE_SHOT)
	{}

	bool handle(TraceeProgram &traceeProg)
	{
		m_syscall_inject.execute(traceeProg);
        return true;
	}
};

#endif