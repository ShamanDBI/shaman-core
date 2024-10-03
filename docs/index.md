# Shaman DBI

Architecture Neutral DBI for Embedded systems

## Why did I create this tool?

1. Security Assessment of Linux Based IoT Devices.
1. This tool is specifically targeted for old version of linux where it difficult to find any debugging or instrumentation tools.
1. Binary analysis are usually re-usable across different projects
1. Add support to as many ISA Architecture as possible.

## Important Features

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
    1. Tracing Data traveling across different process
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

This Framework is intended to be extend and tooling for specific use-cases. You can think of Framework as a High Performance Programming Debugger.
Event Driven Programming

You have two Major interface for Programming. First is 
The functionality can be broadly classifed into two Inteface:
1. Breakpoint - This is to stop the program at arbitrary point in to program.
1. System Call - Whenever the program make a System Call. 

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

Often while reversing you are interested in tracking the data coming in and out of the system this is usually happens via File, Sockets of IPC. Syscall tracing can help you with this task, but practically speaking you can not tracing all the network socket or files because process will open lot of them which are unrelated to your task at hand. While you are reversing you are laser focus on one network socket data and its execution in the binary. So, what you are really interested in is all the system call which are made for read/writing to particular socket file descriptor. So, If you are reversing server binary you are interested in new client connect to server ports and what data is exchanged with the client. Or, if you are reversing client binary you are interesting in tracing data which is exchange on particular port. This exactly what resource tracing can help you to achieve. 

Speaking in Linux terms a file descritor is the *Resource* a unique identifier provided to you by the Kernel, but there is File/Socket resource in the Kernel which has a set of Syscall which operate on it like Reading/Writing configring via IOCTL calls. Resource tracer will give a callback interface to write a custom code.

System Call have overlapping functionality based on the type of Resource on which they operate, For example socket, bind, connect and listen are used to create, listen and close Network connection, these System Call don't operate in isolation. Some of the most comman type of Resource which a OS provides are File, Network, IPC, Process Management, Time, etc. So we categories each System call by this Categories. You can refer to this [link](https://linasm.sourceforge.net/docs/syscalls/index.php), it gives you categorization of different System Call you a very good overview of different category of System Call and their documentation of respective system call.

Resource Tracing gives you an interface for tracing different Resource a Process uses. The interface exposes life-cycle method of resource. A resource Life-cycle includes creation of resource manipulation and closing of resource. This method of tracing give you access to different granility of Reverse Engineering. Tracing Individual System Call is a make sense when you want to take decision soley on the syscall for example getting time from Kernel.

But when you want to doing Attack surface enumeration you want to Trace the data coming and going out of the system you not looking at the indiviual System calls you focus is on the System Resource, like Data coming from Network is exposing you application to remote attacks, IPC resource is exposing your Process to other running Processes in the System, File Resource is exposing to the untrusted data from the file system that any user can write on the system. Similar argument can be made for Reverse Engineering Data recieved on the Network socket or reading from the File format reversing.

While Resource Interface is give you option trace all the Resource in the system but thats not practical and that will would generate over-welming amount of data to process, and you might be only interested in tracing specific Resource, like specific client socket or Particular File on file system. Resource Tracing API provides you `onFilter` function give you a peek al the File Create or Open system call based on the syscall you can decide if you are interested in tracing, to implement your logic which will decide you are interesting in trace the Resource. If `onFilter` function return true the the Resource which is create will added to list of actively traced Resource. Actively Tracing Resource means we are interested in every transaction done on that Resource which mean through Resource Interface you will get callback on every System Call.

Different types of Resource provide different type of callbacks. For example for File Operation you will get callback for Open, Read, Write, Close, etc. You can explore the details of the Interface on FileOperationTracer. Similary Network Sockets exposes some what similar callback, apart from callbacks for Open, Read, Write and Close. Network Resource different from file, A process can create Server Socket will is accepting Client connections and each client get its individual File Descriptor and returning True will only trace that Client Socket. While on the Client side, client might be creating socket connection to different Servers you might be interested in one connection. The traceing is automatically removed when the resource is closed.

There is a system call to create new file or open and exiting one, there are calls to query information about the file.

When we talk about Resource have a Life-cycle, there are three category of the lifecycle method: 
1. *Create or Open* existing Resource for example Create a Network Socket or Open a file from file system. All the System Call falling is this category invoke `onFilter` to decide if the Resoure has to be traced throught it lifecyle. This is case `onOpen` lifecycle method is called.
1. *Consume* There are calls to manipulate the Resource like reading, writing to file descriptor. Based on type of resource all the system Call have a callback method. 
1. *Relase* Finally there is system call to release the Resource for Example close System call. Since the Resource we are tracing no long exist tracing after this point is not done. For this case `onClose` callback is invoked.

We will refere to this flow as *create-consume-release*

The following set of interface provide you the ability to register a callback whenever a Process is attempting to creating a new Resource and give you a chance to peek at the parameter and decide if you are intereted in Tracing the entire life-cycle *create-consume-release* of the Resource. At present we have support for Network(NetworkOperationTracer) and file operation(FileOperationTracer) more will be added soon.

## Adding Support New Architecture

The Question comes in mind is *What if I want to add Support for New Architecture?*. Its actually not too much of work!

There are three places where archiecture specific support is needed
1. Breakpoint Handling - Injecting and Restoring Breakpoints
1. System Call Tracing - Handling System Call parameter
1. Register Interface - using and collecting CPU Registers
