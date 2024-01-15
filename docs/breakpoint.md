# Breakpoint

This another primitive of the Framework

## When to Use it

When you want to stop the program and arbitrary point and inspect the process.

## Keep In Mind

Performance

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

	bool handle(DebugOpts &debug_opts)
	{
		m_syscall_inject.execute();
	}
};

```