.. shaman documentation master file, created by
   sphinx-quickstart on Fri Nov 15 21:35:00 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Shaman DBI
==========


Shaman is a platform-independent Dynamic Binary Analysis Framework designed to instrument programs without needing to recompile them or access their source code. It currently supports Linux (x86_64, ARM, ARM64) and Android (ARM64).

Think of it as a high-performance, scriptable debugger that can pause a program at any point to inspect or modify its memory and registers. This functionality enables tasks like tracing or altering System Call parameter, Injecting System calls, Collecting binary code-coverage, and intercepting or modifying function parameters.

The framework aims to simplify writing plugins and make it fast and easy to support new platforms, such as RISC-V, Power PC, MIPS, etc.

.. toctree::
   :hidden:
   :maxdepth: 1
   :caption: Table of Content

   getting_started.rst
   breakpoint.rst
   syscall_tracing.rst
   code_coverage.rst
   resource_tracing.rst
   porting_guide.rst
   technical_details.rst
   roadmap
   use_cases