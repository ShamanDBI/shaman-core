===============
Getting Started
===============

Why ?
=====

This project began as a curiosity-driven attempt to create my own instrumentation and debugging tool. As I developed it further, I became interested in using it to gather code coverage on black-box binaries. Working on adapting it for different targets led me to design APIs that abstracted these capabilities into a broader framework.

Other instrumentation tools on the market cover a wide range, from full-system instrumentation tools like DynamoRIO, Intel Pintool, Frida, and Valgrind, which can be complex and come with significant performance overhead, to selective instrumentation tools like TinyInst and Mesos, which use various techniques to target specific areas. This framework leans toward selective instrumentation, offering APIs for customized instrumentation of specific targets.

This framework provides an interface that allows easy adaptation to other operating systems and architectures like RISC-V and PowerPC. It also includes unique features, such as system call injection, resource tracing, and real-time code coverage streaming, all accessible via APIs.

With this framework, I aim to consolidate dynamic reverse-engineering techniques scattered across different projects into a comprehensive set of APIs. It is especially intended for reverse-engineering binaries where source code is unavailable.

How to use Shaman Framework?
============================

Shaman is designed as a framework for building tools using its APIs. Many features are provided through classes that can be inherited to implement your own logic, which you then register with the `Debugger` class. You can find more details about the APIs in the [next section](#instrumentation-api).

To start instrumenting your target, first create an instance of the `Debugger` class and pass in a `TargetDescription`, which specifies the architecture of the program being executed. If you want to trace system calls, call `traceSyscall()`, and if you want to trace child processes, use `followFork()`. You can then attach to a running process with `debug.attach(pid)` or start a new process with `debug.spawn("program param")`.

After configuring the debugger, execute it with `debug.eventLoop()`. This function is a blocking call that returns when the tracee completes execution or crashes. Be sure to register all events, like breakpoints and system calls, before calling this function.

Instrumentation API
===================

Breakpoint Callback
-------------------

:doc:`see <code_coverage>`

Binary Code-Coverage
--------------------

:doc:`see <code_coverage>`

Syscall Tracing Callback
------------------------

:doc:`see <syscall_tracing>`

Syscall Injection API
---------------------
:doc:`see <code_coverage>`

Resource Tracing
----------------

:doc:`see <resource_tracing>`

Dependencies
============

Ubuntu
------


Building
========

.. code-block:: console

    make -j 16
    ./scripts/build.sh


Platform Support
================

+----------+--------+-----+-------+---------+---------+
| Platfrom | x86_64 | ARM | ARM64 | MIPS    | RISC-V  |
+==========+========+=====+=======+=========+=========+
| Linux    | Yes    | Yes | Yes   | Planned | Planned |
+----------+--------+-----+-------+---------+---------+
| Android  | No     | No  | Yes   |         |         |
+----------+--------+-----+-------+---------+---------+