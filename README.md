# Shaman DBA

```
 .d8888b.  888    888        d8888 888b     d888        d8888 888b    888      8888888b.  888888b.         d8888 
d88P  Y88b 888    888       d88888 8888b   d8888       d88888 8888b   888      888  "Y88b 888  "88b       d88888 
Y88b.      888    888      d88P888 88888b.d88888      d88P888 88888b  888      888    888 888  .88P      d88P888 
 "Y888b.   8888888888     d88P 888 888Y88888P888     d88P 888 888Y88b 888      888    888 8888888K.     d88P 888 
    "Y88b. 888    888    d88P  888 888 Y888P 888    d88P  888 888 Y88b888      888    888 888  "Y88b   d88P  888 
      "888 888    888   d88P   888 888  Y8P  888   d88P   888 888  Y88888      888    888 888    888  d88P   888 
Y88b  d88P 888    888  d8888888888 888   "   888  d8888888888 888   Y8888      888  .d88P 888   d88P d8888888888 
 "Y8888P"  888    888 d88P     888 888       888 d88P     888 888    Y888      8888888P"  8888888P" d88P     888 
```

Architecture Neutral DBA for Embedded Systems

## Build


```shell
cmake -S . -B build
cmake --build build --target shaman
```

## Dependencies

1. Kaitai - data structure formating and parsing framework
1. Capstone Engine - Disassembly Engine
1. Keystone Engine - Assembler Engine
1. lief - executable parsing framework
1. Linux OS - 2.5 an above

## Challenges

### Multi-threaded Breakpoint handling

The issue here is mulitple threads are sharing same data and code. And adding and remove breakpoints requires you to edit code which is shared between all threads.
The problem arises when a thread A hits a breakpoint to step-over is we have to remove the breakpoint and once the original instruction is executed it places the breakpoint back at that point. while it is doing that a thread B will be running the same instruction where the breakpoint was placed. So thread B misses the breakpoint event.

1. Case 1 - Two threads are operating on different section of the code. This is really not a problem out tool currently supports this feature.
1. Case 2 - Two threads running the same section of the code. This is little challenging to solve currently we are working on this.

## Developing for Different Architecture

Us buildroot to compile the VM and OS tools. It will generate all the necessary toolchain, libraries and Qemu machine.


