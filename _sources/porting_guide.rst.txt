=============
Porting Guide
=============

The Question comes in mind is *What if I want to add Support for New Architecture?*. Its actually not too much of work!

There are three places where archiecture specific support is needed

1. Breakpoint Handling - Injecting and Restoring Breakpoints
1. System Call Tracing - Handling System Call parameter
1. Register Interface - using and collecting CPU Registers
