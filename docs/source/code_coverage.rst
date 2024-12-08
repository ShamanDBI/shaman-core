=============
Code Coverage
=============

Code coverage is a important piece of information when you are reverse-engineering program. This metrics helps you to assess which part of the code has been excercised. If you are reverse engineer you can use this information to narrow down you search to specific code-path. If you are software developer, you can use it to measure the extend to which a software has been tested by the testsuite. If you fuzzing a target you can used this to understand what code is fuzzed and where you need to focus next.

There are different ways in which you can collect this information one is static instrumentation and other is dynamic instrumentation. Both of these technique have their strength and weakness which are discussed in the following sections.

.. note::

    Instrumentation is the act of modifying software so that analysis can be performed on it. It can be done by either modifing source code or binary code.

    Instrumentation is limited by execution coverage. If the program never reaches a particular point of execution, then instrumentation at that point collects no data.

    - Wikipedia

Next few sections are going to expand on the idea of static and dynamic instrumentation. If you are already ware about this and you want to straight away jump on to :ref:`Usage section <code_cov_usage>`.

Source-Base Instrumentation
===========================

This techinque is mostly used by compiler, by enabling certain flags in you builds you can enable this feature. Compiler insert coverage instrumentation code in the compiled binary which record and report this information when the program is executed.

Some promimente tool in this space are gcov for gcc compiler, llvm this feature `llvm_cov`_. There are also other commercial solution like Bullseye.

This solution is mostly source-based that means you need to have *access to source-code* and, you need to recompile the project so that source can be instrumented.

To generate coverage you need to run the instrumented program, which will write the coverage data to the file. The compiler-suite has a program which can consume this file to generate an html report. This report highlights the executed code with the number of time the line is executed.

Now, lets discuss what are the advantages and limitation of this method.

Advantage
---------

#. you get very accurate code coverage with each light highlighted with number of time the code was executed. 

#. Since the compiler has the acces to rich information to coverage trace and 
optimizations should have no impact on coverage report quality. 

#. This option is very easy to follow and get the results.

Limitation
----------

#. You cannot use this if you don't have access to source code or if you don't know how to recompile the program.
#. Instrumentation will slowdown the program execution drastically which can become of problem in situation where performance of the real program might affect its functionality. like a game application, embedded systems.

#. You cannot do selective instrumentation, meaning you are only interested in collecting coverage for paritcular module, function or class. Doing this can restored some of the performance of the program lost due to coverage instrumentation.

#. You only have one option to dump the coverage which is file, this can drastically slowdown the overall activity of coverage reporting. Imagine if you can collect the coverage data in a shared memory buffer or stream it over network socket and collect it on different device.
environments that lack a filesystem

Binary Instrumentation
======================

This approach dynamically modifies the program to insert code which will report the execution trace. This method provides more flexibility since you can dynamically add/remove instrumentation, this setting give you the ability to add business logic to the tracing. Besides this you have many advantages like

#. In fuzzing use cases you can dynamically add/remove instrumentation if get more performance like 
#. You can share the coverage data via different channels like shared memory(like AFL) or network sockets.
#. You can dynamically attach to a running process and stream the code coverage in real-time without terminating process or recompiling the project.

Advantages
----------

#. One solution to above problem is that once we have collected execution trace for a particular code we can restore the original code but this is not possible compile-time instrumentation settings.
#. You can only collect execution trace, you cannot configure the tool to collect any other type of data. Like function parameters, Register values or stack trace of function.

Limitations
-----------

#. Coverage report as not very accurate.
#. This technique is limited by the instrumentation tool is avaliable for the platform for ceamp

When to Use it?
===============

#. Black box target
#. selective instrumentation
#. Custom logic on coverage like single shot breakpoint,
#. 

Keep in Mind
============

Code coverage uses breakpoint to trace execution path, this means breakpoint will be place on all the possible path in the binary and when the breakpoint is hit coverage is registered for that piece of code. 

Instrumentation is done at basic-block level and to identify basic-blocks address we currently rely on disassembler like Ghidra. This also limits the accuracy of instrumentation to what disassembler was able to identify those address 

Instrumentation is limited by execution coverage. So, if the program never reaches a particular point of execution, then instrumentation at that point collects no data.

.. warning::

    There is performace hit associated with breakpoint which is highlighted in see :ref:`this section <breakpoint-warning>`

.. _code_cov_usage:

Usage Guide
===========

#. First you need to identify basic block

:cpp:class:`BreakpointReader` :cpp:class:`BreakpointCoverage`

Footnotes
=========

#. .. _llvm_cov: https://clang.llvm.org/docs/SourceBasedCodeCoverage.html.
#. MPLAB Code Coverage by Micro Chip for Micro-controller
#. https://ldra.com/capabilities/code-coverage-analysis/#CA14
#. Bullseye Testing Technology
#. https://www.qt.io/product/quality-assurance/coco
#. [TestCocoon](https://www.testcocoon.org/download.tmp.html)
#. OS-less dynamic binary instrumentation for embedded firmware