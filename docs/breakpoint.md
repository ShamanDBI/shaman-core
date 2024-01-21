# Breakpoint

This another primitive of the Framework

## When to Use it

When you want to stop the program and arbitrary point and inspect the process.

## Keep In Mind

There is a performace cost associated with breakpoint handling. When there is a breakpoint hit there will be context switching from Tracee process to the Debugger process which is very heavy. This might reduce the performance of the Tracee process. In some cases this might have real impact on the real program. To above this you can do the following:
1. Install One-Shot breakpoint, which is remove after the first hit. This is helpful in things like code coverage
1. You can have breakpoint which has executed only N-time by setting `setMaxHit` count

## Sample Code

```CPP

/// @brief Breakpoint to faciliate syscall injection
class SyscallInjectorBreakpoint : public Breakpoint
{
	SyscallInjector &m_syscall_inject;

public:
	SyscallInjectorBreakpoint(std::string &mod_name, std::uintptr_t bkpt_offset,
							  SyscallInjector *_sys_inject)
		: m_syscall_inject(_sys_inject),
		  Breakpoint(mod_name, bkpt_offset, SINGLE_SHOT)
	{}

	bool handle(TraceeProgram &traceeProgram)
	{
		/**
		 * Implement the breakpoint login in the function
		 * 
		 * You do stuff like :
		 * 1. Read the content of the Register or memory location
		 * 2. Change the content of Memory or Register
		 * 3. Register a new Breakpoint or syscall tracer
		 * 4. Log data to file
		 * 
		 */
	}
};

```