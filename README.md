# Shaman DBI

Shaman is a platform-independent Dynamic Binary Analysis Framework designed to instrument programs without needing to recompile them or access their source code. It currently supports Linux (x86_64, ARM, ARM64) and Android (ARM64).

Think of it as a high-performance, scriptable debugger that can pause a program at any point to inspect or modify its memory and registers. This functionality enables tasks like tracing or altering system call parameters, injecting system calls, collecting binary code coverage, and intercepting or modifying function parameters.

The framework aims to simplify writing plugins and make it fast and easy to support new platforms, such as RISC-V, PowerPC, MIPS, etc.

# Documentation

Documentation is available at [Shaman DBI Documentation](https://shamandbi.github.io), including quickstart guides.

> **Note**: Shaman is an evolving beast, lot of feature are work in progress. We invite you for feedback as well as direct contributions in the form of pull request. If you have facing a any challange or have a suggestions, don't hesitate to open an issue.