==========
Breakpoint
==========

Breakpoint can help you to halt a program at any point and examine or change current state of the program, state is mainly register and memory.

This API can be used in many like tracing function parameter and return type or tracing code execution path, etc.

Ability to put breakpoint programmatically can unlock many possibilites like debugging complex use-cases which can involve multiple-thread co-ordinating with each other to multiple independent proceses working with each other with using IPC mechanism.

Breakpoint is we are talking about are software breakpoint which patches the instruction at which we are interested in halting the program with breakpoint instruction.

When to Use it
==============

When you want to stop the program and arbitrary point and inspect the process.

.. _breakpoint-warning:

Keep In Mind
============

There is a performace cost associated with breakpoint handling. When a breakpoint hit, there will be context switching from Tracee process to the Debugger process which is very costly. This might reduce the performance of the Tracee process. In some cases, this might have real impact on the process execution, say another process expecting the child process to complete the execution in certain time period. 

To deal with this you can do the following:
1. Install One-Shot breakpoint, which is remove after the first hit. This is helpful in things like code coverage
1. You can have breakpoint which has executed only N-time by setting `setMaxHit` count

Example Code
------------

.. code-block:: cpp

	class CodeTracingBreakpoint : public Breakpoint {

	public:
		CodeTracingBreakpoint(std::string &mod_name, std::uintptr_t bkpt_offset)
			: Breakpoint(mod_name, bkpt_offset, SINGLE_SHOT)
		{
			// Initalize some random stuff which you bother to track
		}

		bool handle(TraceeProgram &traceeProgram) {
			/**
			* Implement the breakpoint logic in the function
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
