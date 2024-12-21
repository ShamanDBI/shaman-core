================
Resource Tracing
================

.. _resource-def:

What is a Resource?
===================

A system call (syscall) is an interface provided by the kernel to user-space applications for requesting various services. These services abstract the complexities of hardware and software resources, offering a consistent interface for interacting with them. Software resources can be categorized into different types, such as files, networks, and inter-process communication (IPC).

The kernel provides syscalls to manipulate these software resources. For example, sockets can be created using the `socket` syscall. Once a socket is created, data can be sent and received over the network using syscalls like `sendto`, `sendmsg`, `recvfrom`, and `recvmsg`. When communication is complete, the socket can be closed using the `close` syscall. Similarly, for files, you can create a file with the `open` syscall, read and write data using the `read` and `write` syscalls, and close the file with the `close` syscall.

This is a simplified explanation, but it gives an idea of what a resource is. Resources can be classified into several categories, such as files, sockets, IPC, processes and threads, signals, synchronization, system identifiers, device drivers, and time-related resources [1]_. Each syscall belongs to one or more of these categories. For example, the `read` syscall applies to both files and sockets. These classifications are not rigid but provide a useful abstraction for understanding POSIX-compatible operating systems.

.. _resource-ccr:

Resource Life-cycle
===================

Let me explain the typical lifecycle states that a *software resource* goes through in an OS kernel:

1. **Create**: At this stage, a resource is created, such as a socket, a new process, or a file. A unique resource identifier/handler is returned by the syscall at this stage. If you are interested in tracing it, you can record the identifier and use it in subsequent stages.
2. **Consume**: At this stage, the resource is manipulated, configured, or queried using operations like read, write, or IOCTL syscalls, using the unique identifier/handler returned from the previous stage.
3. **Release**: Once done with the resource, it is destroyed with syscalls like *close*. The unique identifier/handle is surrendered to the OS kernel, which may reuse the same identifier for a new resource.

We will refer to this flow as *create-consume-release* in the future.

Each resource has a unique identifier value when created. This value is passed as a parameter to subsequent syscalls while operating on it. In Unix-like OS, the unique identifier is called a *file descriptor*, while in Windows, it is referred to as a Handler/Object.

Not every syscall has such a lifecycle. For example, time-related syscalls simply return the current time of the system, nothing fancy happening here!

When to Use it?
===============

*Resource Tracing* provides an interface for tracing different software resources via the :cpp:class:`ResourceTracer` interface. This interface exposes :ref:`life-cycle <resource-ccr>` methods that get invoked when the resource you are tracing is being operated on.

When reverse engineering a binary, you may be interested in tracing the data coming in and out of the program, usually done via resources like files, sockets, or IPC. The *Resource Tracing* interface gives you the abstraction to trace data via these :ref:`Resources <resource-def>`. This interface exposes callbacks that are invoked while the resource is going through its :ref:`life-cycle <resource-ccr>`. This interface not only provides insight into the resource's lifecycle but also allows you to manipulate the resource at each stage.

For example, if you want to trace the '/home/password' file data, you can get callbacks for all syscalls made on this file, such as *open*, read, and write. In the callback, you can record or modify the parameters. This is similar to *Syscall Tracing*, but with this interface, you subscribe to all events related 
to '/home/password'. You can learn more about the file interface from the :cpp:class:`FileOperationTracer` class.

Another example is tracing a network socket where a client and server communicate via a TCP socket. From the server's perspective, you might be interested in data exchange with a client. The networking subsystem has different lifecycle syscalls to create a socket, listen on it, accept clients, and start exchanging data. All this is exposed through the :cpp:class:`NetworkOperationTracer` interface. When tracing the server binary, you will get a callback every time a new client tries to connect, such as :cpp:member:`NetworkOperationTracer::onClientOpen`.

Keep in Mind
============

You might be wondering if this is similar to *Syscall Tracing*. You are correct; it is essentially an enhanced form of syscall tracing. However, this interface addresses the problem from a different perspective. While a process can perform numerous file and network-related syscalls, you are interested in tracing them in the context of a specific resource, such as a file path or a socket on port 80. If you were to use :doc:`Syscall Tracing<syscall_tracing>`, you would need to write logic to locate the file descriptor of the resource and match the resource descriptor for each syscall. The feature abstracts this boilerplate code via the :cpp:class:`ResourceTracer` abstraction.

Usage Guide
===========

The :cpp:class:`ResourceTracer` interface provides callbacks to trace the lifecycle of a resource.

1. **Create**: System calls in this category invoke the `onFilter` method to determine if the resource should be traced throughout its lifecycle. If so, the `onOpen` lifecycle method is called.
2. **Consume**: Depending on the type of resource, various system calls will trigger corresponding callback methods.
3. **Release**: When the resource is no longer in use, tracing stops. The `onClose` callback is invoked at this stage.

Use-cases
---------

One of the main reasons for designing syscall tracing in a contextual way is to perform attack surface enumeration. When conducting attack surface enumeration, you want to identify the data sources from which data is entering and leaving the program.

System resources are some of these data sources. Instead of looking at individual syscalls, the focus is on the system resource. This feature helps you follow the thread of a particular data source. Some examples of data sources are:

1. Data coming from the network, which exposes your application to remote attacks.
2. IPC resources, which expose your process to other running processes in the system.
3. File resources, which expose your application to untrusted data from the file system that any user can write to.
4. Device drivers, which are exposed by file paths. By tracing file operations, you can follow the communication between the program and the hardware.

Register for Resource Event
---------------------------

The following set of interfaces provides you the ability to register a callback whenever a process is attempting to create a new resource, giving you a chance to peek at the parameters and decide if you are interested in tracing its :ref:`life-cycle <resource-ccr>`. At present, the framework only supports Network (via :cpp:class:`NetworkOperationTracer`) and file operations (via :cpp:class:`FileOperationTracer`), with more to be added soon.

With the `ResourceTracer` interface, you have to override the :cpp:member:`ResourceTracer::onFilter` method, which gets called every time a new resource is being created. For example, a program might be trying to create/open a file, a client might be opening a socket to a server, or a server might be accepting a new client. In each of these cases, the kernel will create a new file descriptor. It is at this point that you have to decide if you are interested in tracing this resource. The goal of the `onFilter` function is to examine the parameters during the resource creation phase and decide if you are further interested in tracing the resource. If the `onFilter` function returns `true`, the resource that is created will be added to the list of actively traced resources. An actively traced resource means you will get a callback for all the syscalls performed on that resource.

For the file and network subsystems, creating a resource means different things. I suggest you read further about this in their respective documentation for :cpp:member:`FileOperationTracer::onFilter` and :cpp:member:`NetworkOperationTracer::onFilter`.

Different types of resources provide different types of callbacks. For example, for file operations, you will get callbacks for open, read, write, ioctl, close, etc. You can explore the details of the interface in :cpp:class:`FileOperationTracer`.

Similarly, sockets in :cpp:class:`NetworkOperationTracer` expose a different set of callbacks. Apart from callbacks like open, read, write, and close, network resources differ from files. A process can create a server socket that accepts client connections, and each client gets its individual file descriptor. Returning `true` will only trace that client socket. On the client side, the client might be creating socket connections to different servers, and you might be interested in one connection. The tracing is automatically removed when the resource is closed/released.

.. note::

    Tracing individual syscalls makes sense when you want to make decisions solely based on the syscall, for example, getting the time from the kernel. However, some syscalls do not have enough context to trace effectively. In such cases, you can use the `SyscallHandler` interface to handle these syscalls more appropriately.


Example Code
------------

1. A good example of a File Resource is implemented in the :cpp:class:`RandomFileData` class, which returns the same sequence of random values every time you read data from `/dev/random`. The class takes a seed value as a parameter, which can be used to randomize the generated data.
2. Another interesting use-case is when a program reads a file, and you want to replace the data with some other data. You can use the :cpp:class:`OverwriteFileData` class. For example, if a binary reads a configuration from a file and you want to change the configuration data without modifying the actual file, you can use this class. This class takes two file path parameters: the first parameter is the file you want to replace, and the second one is the file you want to replace it with.
3. For tracking socket operations, use the :cpp:class:`DataSocket` class.

.. warning::
    Resource Tracing is still a very experimental feature, and the APIs may change significantly.

Footnotes
=========

Some intereseting piece of reading you can do on this subject from below links.

.. [1] `Linux syscall categories <https://linasm.sourceforge.net/docs/syscalls/index.php>`_