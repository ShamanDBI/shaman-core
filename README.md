# Shaman DBI

Architecture Neutral DBI for Embedded systems

## Programming Interface

1. **Breakpoint Handling** - give you programmable opportunity to when the breakpoint is hit. You will have access to program memory and register which you can manipulate when you hit the breakpoint.
1. **System-call handling** - You can get callback handler before entering and after the syscall is serviced by kernel. You can even cancel system and implement jailer. You will get access to program memory and register which you can manipulate at both points i.e. before and after system call.
1. **File Descriptor Trace** - this are more glorified syscall handler, basically you can get callback when there are operation done on File descriptor.
	1. Since there are different category of file descriptor like File, Socket and IPC you can inteface which you can register and manipulate the program memory/register.
	1. You can use it in trace only mode or even maniplate parameter on before and after system calls.
1. Function Hooking and Instrumentation - you can also replace the entire functionality of the function with your assembly code.
1. Basic Block hooking and instrumentation - same as above.

## Dependencies

1. Kaitai - data structure formating and parsing framework
1. Capstone Engine - Disassembly Engine
1. Keystone Engine - Assembler Engine
1. lief - executable parsing framework

## Use Case

1. This can be used to intercept socket operation and used to manipulate data to and from the target program, essentially use it as proxy program
1. Can be used as a tracer that logs specifed register, memory location. this can be dumped to file. This trace can later be loaded in Ghidra to analyze it even futher in more contextual environment.
1. 

## Ref
1. [ARM and MIPS Ptrace Impl](https://github.com/aleden/ptracetricks/blob/main/ptracetricks.cpp)
1. [Writing Debugger in CPP](https://blog.tartanllama.xyz/writing-a-linux-debugger-source-signal/)
