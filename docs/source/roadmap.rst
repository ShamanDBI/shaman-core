=======
Roadmap
=======

Upcoming Features
=================

1. Function Hooking and Instrumentation
    1. Trace the function parameter and its return value.
    1. Replace the entire functionality of the function with your assembly code.
1. Basic Block hooking and Instrumentation
    1. Observe the execution of Basic Block unit of the program.
1. Anti-Debug Bypasses
    1. Framework will figure the different tricks used by the process to bypass anti-debugging mitigaations.
    1. Trace ptrace related system calls and block them
1. Support in Multi-threaded Environment
1. Support for all the above feature in Micro-Controllers.
1. Crash Analysis for Fuzzing.

How to Write Plugins
====================

You have two Major interface for Programming. First is 
The functionality can be broadly classifed into two Inteface:
1. Breakpoint - This is to stop the program at arbitrary point in to program.
1. System Call - Whenever the program make a System Call. 
