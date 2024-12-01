===================
System Call Tracing
===================

This another primitive of the Framework which give you control over the Kernel resource which the Tracee uses. 

Syscall is the API interface between User and Kernel by which it requests a server from the Kernel of the Operating System.

This Interface will give you ability to stop and inspect before and after the System Call is made.
1. A Process interacte with the Operating systems rich functionality it will make system call for things like Creating and Editing Files, Networking related functions, since Linux and Other Unix like OS have standard Kernel interface you can intercept every request that goes to the Kernel it comeback.
1. To take advantage of this feature you can over-ride SyscallHandler class.
1. System Call data is captured in SyscallTraceData class

When to Use it?
===============

When you want to stop the process before and after the System Call is executed. You can log the data or you can change the parameter and return data to the Tracee Process.

1. You can log the parameter and return type of the syscall
2. You can change the parameter and return data of the syscall
3. You can reject the syscall from executing and return value of your choice
4. You can emulate the syscall but not actually executing the syscall and returning a fake value.
5. You cannot change the Syscall number of the parameter.

Keep In Mind
============

There is a performace cost associated with syscall handling.

Sample Code
===========
