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
1. Support for all the above feature in Micro-Controllers.
1. Crash Analysis for Fuzzing.

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

## How to Write Plugins

You can think of Framework as a High Performance Programming Debugger.
Event Driven Programming

You have two Major interface for Programming. First is 

The functionality can be broadly classifed into two Inteface, One is System Call and Breakpoint

### Breakpoint

Breakpoint will give you abilility to stop and inspect at arbitrary point in the process. Initial impression might suggest that its very stop and go interface but think of interesting Points you want to halt the execution and inspect data. This could be at function entry and exit point where you are interested in tracing all the call parameter and their return type. You call trace all the malloc and free calls and catch bugs like double free or resource leakage.

Please refere to [Breakpoint Handling](breakpoint.md) for more detials with code example on how to use the interface. 

### Syscall

Syscall is the API interface between User and Kernel by which it requests a server from the Kernel of the Operating System.

This Interface will give you ability to stop and inspect before and after the System Call is made.
1. A Process interacte with the Operating systems rich functionality it will make system call for things like Creating and Editing Files, Networking related functions, since Linux and Other Unix like OS have standard Kernel interface you can intercept every request that goes to the Kernel it comeback.
1. To take advantage of this feature you can over-ride SyscallHandler class.
1. System Call data is captured in SyscallTraceData class


### Resource Tracing 

System Call are not mode in isolation. The System calls can be grouped into base on type of resource to operate on, For example File is one type of Resource, Network Sockets are another example.

Grouping of the system call by Resources can be grouped into are File, Network, Shared Memory, Process, Time. This [link](https://linasm.sourceforge.net/docs/syscalls/index.php) give you a very good overview of different category of System Call and their documentation of respective system call.

There is a system call to create new file or open and exiting one, there are calls to query information about the file.

Resource have a lifetime, there is a system call to 
1. Create or open existing Resource
1. There are calls to manipulate the Resource and 
1. Finally there is system call to release the Resource.

We will refere to this flow as *create-consume-release*

The following set of interface provide you the ability to register a callback whenever a Process is attempting to creating a new Resource and give you a chance to peek at the parameter and decide if you are intereted in Tracing the entire life-cycle *create-consume-release* of the Resource. At present we have support for Network(NetworkOperationTracer) and file operation(FileOperationTracer) more will be added soon.

## Adding Support New Architecture

The Question comes in mind is *What if I want to add Support for New Architecture?*. Its actually not too much of work!

There are three places where archiecture specific support is needed
1. Breakpoint Handling - Injecting and Restoring Breakpoints
1. System Call Tracing - Handling System Call parameter
1. Register Interface - using and collecting CPU Registers