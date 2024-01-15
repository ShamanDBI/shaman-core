# Shaman DBI

Architecture Neutral DBI for Embedded systems

## Why did I create this tool?

1. Security Assessment of Linux Based IoT Devices.
1. This tool is specifically targeted for old version of linux where it difficult to find any debugging or instrumentation tools.
1. Binary analysis are usually re-usable across different projects
1. Add support to as many ISA Architecture as possible.

## Programming Interface

1. **[Programmatic Breakpoint Handling](breakpoint.md)** - give you programmable opportunity to when the breakpoint is hit. You will have access to program memory and register which you can manipulate when you hit the breakpoint.
    1. Can be used as a tracer that logs specifed register, memory location. this can be dumped to file. This trace can later be loaded in Ghidra to analyze it even futher in more contextual environment.
1. **System Call Tracing** - You can get callback handler before entering and after the syscall is serviced by kernel. You can even cancel system and implement jailer. You will get access to program memory and register which you can manipulate at both points i.e. before and after system call.
1. **Resource Tracing** - this are more glorified syscall handler, basically you can get callback when there are operation done on File descriptor.
	1. Since there are different category of file descriptor like File, Socket and IPC you can inteface which you can register and manipulate the program memory/register.
	1. You can use it in trace only mode or even maniplate parameter on before and after system calls.
1. **Function Hooking and Instrumentation**
    1. Trace the function parameter and its return value.
    1. Replace the entire functionality of the function with your assembly code.
1. **Basic Block hooking and Instrumentation**
    1. Observe the execution of Basic Block unit of the program.
1. **Code Coverage** - Collecting code coverage
    1. This will cover both senarios one were you have access to source code and where you don't have acess.
    1. Post processing of coverage in different programming languages.
1. **Advance Data Tracing**
    1. Tracing Data travelling accross different process
    1. Attaching Debugger to different process/threads and hook their handlers.
    1. Data passing through IPC Mechanics between processing.
    1. This will be achieved by Programmatic breakpoint but on different Process.
1. Anti-Debug Bypasses
    1. Framework will figure the different tricks used by the process to bypass anti-debugging mitigaations.
    1. Trace ptrace related system calls and block them
1. Support in Multi-threaded Environment
1. Support for all the above feature in Micrcontrollers.

## Quick Usage Guide 

```shell
Shaman DBI Framework
Usage: ./build/bin/shaman [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -l,--log TEXT               application debug logs
  -o,--trace TEXT             output of the tracee logs
  -p,--pid INT                PID of process to attach to
  -b,--brk TEXT ...           Address of the breakpoints
  -e,--exec TEXT ... REQUIRED program to execute
  -f,--follow                 follow the fork/clone/vfork syscalls
  -s,--syscall                trace system calls

```

## Adding New Architecture Support

The Question comes in mind is *What if I want to add Support for New Architecture?*. Its actaully not too much of work!

There are three places where archiecture specific support is needed
1. Breakpoint Handling - 
1. System Call Tracing - Handling System Call parameter
1. Register Interface - using and collecting CPU Registers