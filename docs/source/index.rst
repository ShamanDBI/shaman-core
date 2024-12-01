.. shaman documentation master file, created by
   Created on Fri Nov 15 21:35:00 2024.
==========
Shaman DBI
==========

Shaman is a platform-independent Dynamic Binary Analysis Framework designed to instrument programs without needing to recompile them or access their source code. It currently supports Linux (x86_64, ARM, ARM64) and Android (ARM64).

Think of it as a high-performance, scriptable debugger that can pause a program at any point to inspect or modify its memory and registers. This functionality enables tasks like tracing or altering System Call parameter, Injecting System calls, Collecting binary code-coverage, and intercepting or modifying function parameters.

The framework aims to simplify writing plugins and make it fast and easy to support new platforms, such as RISC-V, Power PC, MIPS, etc.

.. image:: _static/shaman-arch.jpg
   :alt: Shaman architecture diagram

Why ?
=====

This project began as a curiosity-driven attempt to create my own instrumentation and debugging tool. As I developed it further, I became interested in using it to gather code coverage on black-box binaries. Working on adapting it for different targets led me to design APIs that abstracted these capabilities into a broader framework.

Other instrumentation tools on the market cover a wide range, from full-system instrumentation tools like DynamoRIO, Intel Pintool, Frida, and Valgrind, which can be complex and come with significant performance overhead, to selective instrumentation tools like TinyInst and Mesos, which use various techniques to target specific areas. This framework leans toward selective instrumentation, offering APIs for customized instrumentation of specific targets.

This framework provides an interface that allows easy adaptation to other operating systems and architectures like RISC-V and PowerPC. It also includes unique features, such as system call injection, resource tracing, and real-time code coverage streaming, all accessible via APIs.

With this framework, I aim to consolidate dynamic reverse-engineering techniques scattered across different projects into a comprehensive set of APIs. It is especially intended for reverse-engineering binaries where source code is unavailable.

How to use Shaman Framework?
============================

Shaman is designed as a framework for building tools using its APIs. Many features are provided through classes that can be inherited to implement your own logic, which you then register with the :cpp:class:`Debugger` class. You can find more details about the APIs in the [next section](#instrumentation-api).

To start instrumenting your target, first create an instance of the :cpp:class:`Debugger` class and pass in a :cpp:class:`TargetDescription`, which specifies the architecture of the program being executed. If you want to trace system calls, call `traceSyscall()`, and if you want to trace child processes, use `followFork()`. You can then attach to a running process with `debug.attach(pid)` or start a new process with `debug.spawn("program param")`.

After configuring the debugger, execute it with `debug.eventLoop()`. This function is a blocking call that returns when the tracee completes execution or crashes. Be sure to register all events, like breakpoints and system calls, before calling this function.

Instrumentation API
===================

Breakpoint Callback
-------------------

You can insert a software breakpoint at any location in the program and receive a callback when it's triggered. To set a breakpoint, inherit from the :cpp:class:`Breakpoint` class and override the :cpp:member:`Breakpoint::handle` function to define your custom breakpoint handling logic. In the :cpp:class:`Breakpoint` constructor, provide the **module name** and the **offset** from the base address. The framework will then automatically calculate the actual breakpoint address and insert the breakpoint for you.

To know more about this :doc:`see <code_coverage>`.

Syscall Tracing Callback
------------------------

This callback provides details about the system calls the program is making, allowing you to intercept the event both before the call reaches the kernel and after it returns. You can override the :cpp:member:`SyscallHandler::onEnter` and :cpp:member:`SyscallHandler::onExit` callbacks to get notifications for every system call the program makes.

Beyond tracing, you can also modify system call parameters before they enter the kernel or adjust the return values after they exit the kernel. Known as system call hijacking, this feature is used by various tools to implement process jailing, which restricts access to certain system files or sockets by failing specific system calls. It can also be used for fuzz testing by modifying system calls that handle file or network data.

To know more about this :doc:`see <syscall_tracing>`.

Binary Code-Coverage
--------------------

Using these features, you can set breakpoints on all basic blocks and collect addresses as each block is executed. This is particularly useful if you don't have access to the source code or cannot recompile the target.

You can also use single-shot breakpoints, which are removed after they're hit. This type of coverage instrumentation can improve performance if you're only interested in knowing whether a specific piece of code has executed.

This feature is already implemented in the :cpp:class:`BreakpointCoverage` and :cpp:class:`BreakpointReader` classes. Basic block addresses for the binary can be identified using disassembly tools like Ghidra or IDA, and a Ghidra script is included in the repository.

Coverage data can be saved to a file using the :cpp:class:`CoverageTraceWriter` class, and you can later process this data with the Python script *coverage_parser.py*.

To know more about this :doc:`see <code_coverage>`.

Resource Tracing
----------------

*Resource Tracing* provides you an interface for tracing different Software Resources via :cpp:class:`ResourceTracer` interface. This interface exposes :ref:`life-cycle <resource-ccr>` method which gets invoked when the resource you are tracing is been operated on.

This features is just a glorified syscall handler, you basically get callback when there are operation done on resource.

To know more about this :doc:`see <resource_tracing>`.

Syscall Injection API
---------------------

This feature allows you to execute system calls within a running process. To use it, inherit from the :cpp:class:`SyscallInject` class and set the system call arguments. Once the injection is complete, the :cpp:member:`SyscallInject::onComplete` callback is triggered, where you can record the system call's return value.

To know more about this :doc:`see <code_coverage>`.

Platform Support
================

+----------+--------+-----+-------+---------+---------+
| Platfrom | x86_64 | ARM | ARM64 | MIPS    | RISC-V  |
+==========+========+=====+=======+=========+=========+
| Linux    | Yes    | Yes | Yes   | Planned | Planned |
+----------+--------+-----+-------+---------+---------+
| Android  | No     | No  | Yes   | No      | No      |
+----------+--------+-----+-------+---------+---------+

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: General

   index.rst
   building.rst
   porting_guide.rst
   roadmap.rst

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Instrumentation API

   breakpoint.rst
   syscall_tracing.rst
   code_coverage.rst
   resource_tracing.rst

.. toctree::
   :hidden:
   :maxdepth: 1
   :caption: Code Indexes
   
   code_index.rst


