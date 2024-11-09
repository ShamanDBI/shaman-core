# What is Shaman?

<img src="docs/shaman-arch.jpg" alt="image" width="50%" height="auto">

Shaman is a platform-independent Dynamic Binary Analysis Framework designed to instrument programs without needing to recompile them or access their source code. It currently supports Linux (x86_64, ARM, ARM64) and Android (ARM64).

Think of it as a high-performance, scriptable debugger that can pause a program at any point to inspect or modify its memory and registers. This functionality enables tasks like tracing or altering System Call parameter, Injecting System calls, Collecting binary code-coverage, and intercepting or modifying function parameters.

The framework aims to simplify writing plugins and make it fast and easy to support new platforms, such as RISC-V, Power PC, MIPS, etc.

# Why ?

This project began as a curiosity-driven attempt to create my own instrumentation and debugging tool. As I developed it further, I became interested in using it to gather code coverage on black-box binaries. Working on adapting it for different targets led me to design APIs that abstracted these capabilities into a broader framework.

Other instrumentation tools on the market cover a wide range, from full-system instrumentation tools like DynamoRIO, Intel Pintool, Frida, and Valgrind, which can be complex and come with significant performance overhead, to selective instrumentation tools like TinyInst and Mesos, which use various techniques to target specific areas. This framework leans toward selective instrumentation, offering APIs for customized instrumentation of specific targets.

This framework provides an interface that allows easy adaptation to other operating systems and architectures like RISC-V and PowerPC. It also includes unique features, such as system call injection, resource tracing, and real-time code coverage streaming, all accessible via APIs.

With this framework, I aim to consolidate dynamic reverse-engineering techniques scattered across different projects into a comprehensive set of APIs. It is especially intended for reverse-engineering binaries where source code is unavailable.

# How to use Shaman Framework?

Shaman is created with the intention to create tools using its API's, its meant to be a framework. Much of the features are exposed via classes which you need to in-herit and implement your logic and register it with the `Debugger` class. You can learn more about the API's in [next section](#instrumentation-api).

To start debugging you need to create `Debugger debug(targetDesc)` with `TargetDescription` which describes the target architecture. Then you can either attach to a running process with `debug.attach(pid)` function or you can spawn a new process with `debug.spawn("program param")`.

Once you have configured debugger class, you can execute debugger with `debug.eventLoop()`. This function blocking call which returns when the tracee completes its execution or it crashes. All the event registration like breakpoint and system calls should be done before the function call.

# Instrumentation API

## Breakpoint Callback

You can insert the software breakpoint at any point in the program and get callback when the breakpoint is hit. To register a breakpoint you have to inherit `Breakpoint` class and override `handle` function which has you custom breakpoint handling function. In the `Breakpoint` constructor you have to provide the *module name* and the *offset* from the base address.

```cpp
class BreakpointCoverage : public Breakpoint
{
	std::shared_ptr<CoverageTraceWriter> m_trace_writer;
	uint16_t m_module_id = 0;

public:
	BreakpointCoverage(
		std::shared_ptr<CoverageTraceWriter> trace_writer,
		std::string &modname, uintptr_t offset)
		: Breakpoint(modname, offset),
		  m_trace_writer(trace_writer)
	{
		m_module_id = m_trace_writer->get_module_id(modname);
	}

	virtual bool handle(TraceeProgram &traceeProg)
	{
		Breakpoint::handle(traceeProg);
		m_log->warn("{} {} {:x}", traceeProg.pid(), m_module_id, m_addr);
		m_trace_writer->record_cov(traceeProg.pid(), m_module_id, m_addr);
		return true;
	}
};
```

```cpp

debug.addBreakpoint(brk_pnt_addrs);
```

## Binary Code-Coverage

You can use the previous features to breakpoint on all the basic block and collect the address when the basic block is hit while the program is executing. This can be useful in-case you don't have access to source-code or cannot recompile the target. 

One can also have a single-shot breakpoint which is a type of breakpoint which remove once it is hit, this type coverage instrumentation can improve the performance in-cases where you are only interested in know if a particular piece of code has executed on not!

This feature is already implement with `BreakpointCoverage` and `BreakpointReader` class. Basic block address for the binary can be found by using disassembler Ghidra/IDA. Script for Ghidra is already included in the repository.

Coverage data can be dump in a file which is done using `CoverageTraceWriter` class. You can later process the coverage data using python script *coverage_parser.py*.

## Syscall Tracing Callback

This callback gives you details about what system call program is making you get to intercept the event before the system call goes to the kernel and once the system call is returned. You can over-ride the `onEnter` and `onExit` callback to get notified for all the syscall the program is making. 

Tracing is not the only thing you can do, you can also modify the system call parameters before it enter the kernel or modify the value once it return from the kernel. This feature is also called system call hijacking used by different tools to implement process jailing which basically doesn't give access to different system file/socket by failing the system call. This feature can also be used to fuzz application by replacing system call reading file or network data.

This feature is exposed via `SyscallHandler` class. You have to inherit the calls and override the `onEnter` and `onExit`, each of these function have SyscallTraceData as parameter which gives you syscall parameter.

```cpp
class OpenAtHandler : public SyscallHandler {

public:
    /// this handler will be registered for openat system call
	OpenAtHandler() : SyscallHandler(SysCallId::OPENAT) {}

	int onEnter(SyscallTraceData &sc_trace)
	{
		m_log->debug("openat : onEnter");
		m_log->debug("openat({:x}, {:x}, {}, {})", sc_trace.v_arg[0], sc_trace.v_arg[1], sc_trace.v_arg[2], sc_trace.v_arg[3]);
		return 0;
	}

	int onExit(SyscallTraceData &sc_trace)
	{
		m_log->debug("openat : onExit");
		m_log->debug("openat() -> [{}]", sc_trace.v_rval);
		return 0;
	}
};
```
## Syscall Injection API

Using this feature you can execute System call in a running process. To using this feature you have to inherit `SyscallInject` class and set the argument of the Syscall, on the injection is completed `onComplete` callback is called, you can use this callback function to record the return value of the syscall.

In case of example below we are executing mmap system call in the target process to allocated a page with read write permission and once the system call is completed it gets a callback on the `onCompelete` it records the return value of the system call. This memory can be later be utilzed to write custom shellcode in the target process.

```cpp
class MmapSyscallInject : public SyscallInject
{

	std::shared_ptr<spdlog::logger> m_log = spdlog::get("main");
	AddrPtr m_mmap_addr = nullptr;

public:
	MmapSyscallInject(uint64_t mmap_size) : SyscallInject(ARM_MMAP2)
	{
		m_mmap_addr = new Addr();
		m_mmap_addr->setRemoteSize(mmap_size);
		setCallArg(0, 0);
		setCallArg(1, mmap_size);
		setCallArg(2, PROT_READ | PROT_WRITE);
		setCallArg(3, MAP_PRIVATE | MAP_ANONYMOUS);
		setCallArg(4, -1);
		setCallArg(5, 0);
	}

	void onComplete()
	{
		/**
		 * Check the return value an do some error handling and logging
		 */
		uintptr_t mmap_addr = m_ret_value;
		m_mmap_addr->setRemoteAddress(mmap_addr);
		m_log->info("Page allocated at address 0x{:x}", mmap_addr);
	}
};
```

# Building Shaman

```bash
cmake -S . -B build
cmake --build build --config Release
```

# Quick Usage Guide

# Usage

You can dump the program basic block address using Ghidra SRE tool and 

```bash
<ghidra path>/support/analyzeHeadless tmp_proj HeadlessAnalysis -import ./build/bin/test_prog -scriptPath /home/hussain/ghidra_scripts/ -postscript export_basic_block.py
```

# Platform Support

| Platform | x86_64 | ARM | ARM64 |
|---|---|---|---|
| Linux | Yes | Yes |Yes |
| Android | No | No |Yes |

# Limitations

- The whole instrumentation is currently based on ptrace API which is not very good if you are looking for performance since there is a cost of context switching between debugger and the debuggee process everytime there is breakpoint or system call.
- To collect binary code coverage we need the basic block addresses for the program, to identify these address currently the framework depends on disassembler tools like Ghidra SRE. But the problem is that any disassembler tools is not 100% accruate in identifying all the basic blocks which can lead to in accurate coverage report.  



