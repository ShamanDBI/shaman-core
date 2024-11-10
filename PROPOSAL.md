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

Shaman is designed as a framework for building tools using its APIs. Many features are provided through classes that can be inherited to implement your own logic, which you then register with the `Debugger` class. You can find more details about the APIs in the [next section](#instrumentation-api).

To start instrumenting your target, first create an instance of the `Debugger` class and pass in a `TargetDescription`, which specifies the architecture of the program being executed. If you want to trace system calls, call `traceSyscall()`, and if you want to trace child processes, use `followFork()`. You can then attach to a running process with `debug.attach(pid)` or start a new process with `debug.spawn("program param")`.

After configuring the debugger, execute it with `debug.eventLoop()`. This function is a blocking call that returns when the tracee completes execution or crashes. Be sure to register all events, like breakpoints and system calls, before calling this function.

# Instrumentation API

## Breakpoint Callback

You can insert a software breakpoint at any location in the program and receive a callback when it’s triggered. To set a breakpoint, inherit from the `Breakpoint` class and override the `handle` function to define your custom breakpoint handling logic. In the `Breakpoint` constructor, provide the **module name** and the **offset** from the base address. The framework will then automatically calculate the actual breakpoint address and insert the breakpoint for you.

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

int main() {
	// create the debugger instance
	Debugger debug(targetDesc);
	
	// attach to the running process
	debug.attach(pid);

	// register for system call event
	debug.addSyscallHandler(new OpenAtHandler());
	debug.addBreakpoint(brk_pnt_addrs);
}
```

## Binary Code-Coverage

Using these features, you can set breakpoints on all basic blocks and collect addresses as each block is executed. This is particularly useful if you don't have access to the source code or cannot recompile the target.

You can also use single-shot breakpoints, which are removed after they’re hit. This type of coverage instrumentation can improve performance if you're only interested in knowing whether a specific piece of code has executed.

This feature is already implemented in the `BreakpointCoverage` and `BreakpointReader` classes. Basic block addresses for the binary can be identified using disassembly tools like Ghidra or IDA, and a Ghidra script is included in the repository.

Coverage data can be saved to a file using the `CoverageTraceWriter` class, and you can later process this data with the Python script *coverage_parser.py*.

## Syscall Tracing Callback

This callback provides details about the system calls the program is making, allowing you to intercept the event both before the call reaches the kernel and after it returns. You can override the `onEnter` and `onExit` callbacks to get notifications for every system call the program makes.

Beyond tracing, you can also modify system call parameters before they enter the kernel or adjust the return values after they exit the kernel. Known as system call hijacking, this feature is used by various tools to implement process jailing, which restricts access to certain system files or sockets by failing specific system calls. It can also be used for fuzz testing by modifying system calls that handle file or network data.

This functionality is available through the `SyscallHandler` class. To use it, inherit from the class and override `onEnter` and `onExit`. Each of these functions takes a `SyscallTraceData` parameter, which provides access to the system call parameters.

Below is an example which intercepts *openat* System Call at both entry and exit point. You can register for the event by calling `addSyscallHandler`.

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

int main() {
	// create the debugger instance
	Debugger debug(targetDesc);
	
	// attach to the running process
	debug.attach(pid);

	// register for system call event
	debug.addSyscallHandler(new OpenAtHandler());
}
```

## Syscall Injection API

This feature allows you to execute system calls within a running process. To use it, inherit from the `SyscallInject` class and set the system call arguments. Once the injection is complete, the `onComplete` callback is triggered, where you can record the system call’s return value.

In the example below, we execute the `mmap` system call in the target process to allocate a page with read-write permissions. When the system call completes, the `onComplete` callback records its return value. This allocated memory can then be used to write custom shellcode into the target process.

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

		// set the value of the argument to be instected
		setCallArg(0, 0);
		setCallArg(1, mmap_size);
		setCallArg(2, PROT_READ | PROT_WRITE);
		setCallArg(3, MAP_PRIVATE | MAP_ANONYMOUS);
		setCallArg(4, -1);
		setCallArg(5, 0);
	}

	void onComplete()
	{
		// once the system call is executed successfully the
		// return value of the mmap is address of the page allocated
		// we can record this which will be used in the future
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

# Usage Guide

There are two sample application which are included in the *examples* directory. They are described in the next section

## System Call Interceptor

This project demonstrate how to use system call tracing API's, it has some sample *openat* syscall handler liek `OpenAt1Handler` and `OpenAt2Handler`. You can find the code in [examples/syscall_tracer](examples/syscall_tracer/main.cpp).

## Binary Coverage Application

This project demonstrate how to collect binary code-coverage for binary. First you need the address of all the basic blocks, this can be extracted using Ghidra Script using this [script](script/ghidra_bb_expoter.py)

Following commands will help you to build the framework and the application

```bash
# build the core framework
cmake -S . -B build_lib

# build the coverage app
cmake -S binary_coverage -B binary_coverage_app
cmake --build binary_coverage_app
```

To execute the script down the Ghidra and the run the below command

```bash
<ghidra path>/support/analyzeHeadless tmp_proj HeadlessAnalysis -import ./build/bin/test_prog -scriptPath /home/hussain/ghidra_scripts/ -postscript ghidra_bb_expoter.py
```

To execute the application you need to run the following command

```bash
eagle_coverage_app/eagle_coverage -l app.log --cov-basic-block ./test_prog_1.bb --cov-out test_app.cov -e ./test_target/bin/test_target 1
```

# Platform Support

| Platform | x86_64 | ARM | ARM64 |
|---|---|---|---|
| Linux | Yes | Yes |Yes |
| Android | No | No |Yes |

# Limitations

This framework is work-in-progress which means there are lot of design  decision taken are not permanent and are subjected to change if more optimial solution found.

- The whole instrumentation is currently based on ptrace API which is not very good if you are looking for performance since there is a cost of context switching between debugger and the debuggee process everytime there is breakpoint or system call. This method simplifies the hooking primitive if you want to add support for new architecture. To add support for program halting you have to add support for breakpoint for that architecture and you have all the tracing feature available.
- To collect binary code coverage we need the basic block addresses for the program, to identify these address currently the framework depends on disassembler tools like Ghidra SRE. But the problem is that any disassembler tools is not 100% accruate in identifying all the basic blocks which can lead to in accurate coverage report.  

# Inspiration

This project is inspired from other projects like Mesos, TinyInst and Frida. Some of the functionality has been borrowed from these projects.