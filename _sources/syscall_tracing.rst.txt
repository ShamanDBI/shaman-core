===================
System Call Tracing
===================

This another primitive of the Framework which give you control over the Kernel resource which the Tracee uses. 

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
