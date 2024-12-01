================
Resource Tracing
================

.. _resource-def:

What is a Resource?
===================

System call(syscall) is interface the kernel provides to user-space to request for services. These services are abstraction for the complexity of hardware and software resources and provide a consistent interface to interact with these resources. *Software Resource* can be classified into different categories like file, network, inter-process communication(IPC), etc.

Kernel provides syscall to manipulate these software resources for example, *Sockets* can be create using *socket* syscall, once you have created the socket you can send and recieve data over the network using syscalls like sendto, sendmsg, recvfrom, recvmsg, etc and once you are done with communication you can close the socket using *close* syscall. Similarly kernel provides interface for *Files*, you can create file with *open* system call and then you can read and write data to file using *read* and *write* syscall and once done you can close the file with *close* syscall. 

This is just an over simplification but you should get an idea *what is a Resource*. There are six/seven categories of resource which is File, Socket, IPC, Process & Thread, Signals, Synchronization, System Identifiers, Device Drivers, and Time related, etc [1]_. Each syscall will belong to either one or more of this category. For example *read syscall* belongs to File and Socket. These are by no means a concrete classification but these abstraction can be encountered in almost any POSIX-compatible operating systems.

.. _resource-ccr:

Resource Life-cycle
===================

Let me explain the typical lifecycle states that a *software resource* goes through in an OS kernel:

1. **Create**: At this stage a resource is created like socket, spawning new process or create new file or an existing one is opened like file from the disk for example File. A unique resource identifier/handler is returned by the syscall at this stage. If you are interested in tracing it you can record the identifier and used it in sub-sequent stage.
2. **Consume**: At this stage resource is manipulated, configured or queried upon by operation like read, write, IOCTL syscall call using the unique identifier/handler returned form previous stage.
3. **Release**: Once done with the resource it is destroyed with syscall like *close*. This unique identifier/handle is surrendered to the OS kernel which can be may re-used the same identifier for new resource.

We will refere to this flow as *create-consume-release* in the future.

Each Resource has a unique identifier value when created, this value is passed as parameter to the sub-sequent syscalls while operating on it. Speaking for Unix-like OS the *Resource* a unique identifier is called as *file descritor*, in Windows they calls it as Handler/Objects. 

Not every syscall has such life-cycle, for example time related syscall simply return the current time of the system, nothing fancy happening here!

When to Use it?
===============

*Resource Tracing* provides you an interface for tracing different Software Resources via :cpp:class:`ResourceTracer` interface. This interface exposes :ref:`life-cycle <resource-ccr>` method which gets invoked when the resource you are tracing is been operated on.

While reverse engineering binary a you are interested in tracing the data coming and in out of the program, this is usually done via Resources like File, Sockets or IPC. *Resource Tracing* interface gives you the abstraction to trace data via these :ref:`Resources <resource-def>`. This interface exposes callbacks which are invoked while the Resource is going through the :ref:`life-cycle <resource-ccr>`. The interface tries to give you an exposure into the life-cycle of the resource.

Let take and example of a tracing '/home/password' file data, say you are interested in the getting callback for all the syscall done for a particular file. So, everytime a program makes a syscall like *open*, read, write, you are get a callback to interven. In the callback you can either record the parameter or modify them. You must be wondering isn't this very similar to *Syscall Tracing*, you are right! its just glorified syscall handler. With these interface you subscribing all the events related to '/home/password'. You can learn more about the file interface from this class :cpp:class:`FileOperationTracer`.

Lets take another example for network socket, you have a client and a server talking to each other via TCP socket. Let say from the server perspective you can interested in data exchange via a client. The networking sub-system has different life-cycle syscall to create socket and listen on the socket to accept clients and start exchanging data on it. All this is exposed :cpp:class:`NetworkOperationTracer` interface. So when tracing server binary you will get callback everytime a new client is trying to connect :cpp:member:`NetworkOperationTracer::onClientOpen`.

Keep in Mind
============

You must be wondering isn't this very similar to *Syscall Tracing*, you are right! its just glorified syscall tracing. But this interface is trying to solve a problem in a different context, While a process can operate on lot many files and network related syscall, you are interested in tracing them in context of a particular resource say a file path, or socket on port 80. If you try to trace it with :doc:`Syscall Tracing<syscall_tracing>` you will have to write logic of locate the file descriptor of the resource and match the resource descriptor for each syscall. :cpp:class:`ResourceTracer` interface tries to simply this.

Usage Guide
===========

:cpp:class:`ResourceTracer` provides an callback interface to trace the life-cycle of Resource which we just discussed.

1. **Create**: All the System Call falling is this category invoke `onFilter` to decide if the Resoure has to be traced throught it lifecyle. This is case `onOpen` lifecycle method is called.
2. **Consume**: Based on type of resource all the system Call have a callback method.
3. **Release**: Since the Resource we are tracing no long exist tracing after this point is not done. For this case `onClose` callback is invoked.

Use-cases
---------

One of the main reason for me designing syscall tracing in contextual way is to do attack surface enumeration. When you want to doing Attack surface enumeration you want to know the data sources from which the data is coming in and going out of the program.

System Resources are some of the data source for these attack surface. You not looking at the indiviual syscalls, you focus is on the System Resource. This feature help you to follow the thread of a particular data source for example some of the data sources are:

1. Data coming from Network is exposing you application to remote attacks.
2. IPC resource is exposing your Process to other running Processes in the System.
3. File Resource is exposing to the untrusted data from the file system that any user can write on the system. 
4. Device drivers are exposed by file path by tracing file operations you can follow the communication between program and the hardware.

Register for Resource Event
---------------------------

The following set of interface provide you the ability to register a callback whenever a Process is attempting to creating a new Resource and give you a chance to peek at the parameter and decide if you are intereted in tracing its :ref:`life-cycle <resource-ccr>`. At present framework only supports for Network(via :cpp:class:`NetworkOperationTracer`) and file operation(via :cpp:class:`FileOperationTracer`) more will be added soon.

With ResourceTracer interface you have to override :cpp:member:`ResourceTracer::onFilter` method will gets call everytime a new Resource is getting created for example a program is trying to create/open a file or a client is opening a socket to server, or server is accepting a new client. In each of this cases you are kernel will create a new file descriptor, it is at this point we you hae to decide if you are interested in tracing this resource. The goal of `onFilter` function is into the resource create phase so that you can examine the parameters and decide if you are further interested in tracing the Resource. If the `onFilter` function return `true` the the Resource which is create will added to list of actively traced Resource. An actively traced Resource means you will get a callback for all the syscalls done on that resource.

For file and network sub-system creating a resource means different I would suggest you to read further about in their respective documentation for :cpp:member:`FileOperationTracer::onFilter` and :cpp:member:`NetworkOperationTracer::onFilter`.

Different types of Resource provide different type of callbacks. For example for File Operation you will get callback for open, read, write, ioctl, close, etc. You can explore the details of the Interface on :cpp:class:`FileOperationTracer`. 

Similary sockets :cpp:class:`NetworkOperationTracer` exposes different set of callback, apart from callbacks like open, read, write and close. Network Resource different from file, A process can create Server Socket will is accepting Client connections and each client get its individual File Descriptor and returning True will only trace that Client Socket. While on the Client side, client might be creating socket connection to different Servers you might be interested in one connection. The tracing is automatically removed when the resource is closed/released.

Tracing individual syscall makes sense when you want to take decision soley on the syscall for example getting time from Kernel.


Example Code
------------

1. A very good example of File Resource is implemented in :cpp:class:`RandomeFileData` which basically help return same sequence of random value every time you call read data from `/dev/random`. Class takes seed value as the parameter which can be used to randomize the generated data.
2. Another interesting use-case is when a program file reads a file you want to replace the data it some other data you can use :cpp:class:`OverwriteFileData` class. Say if a binary read a configuration from a file and you want to change th configuration data without modifing the actual file you can use this class. This class take two file path parameter, first paramete is the file you want to replace and 2nd one been the file you want to replace with.
3. For tracking socket operation :cpp:class:`DataSocket`

.. warning::
    Resource Tracing is still a very experimental feature and API's may change a lot.

Footnotes
=========

Some intereseting piece of reading you can do on this subject from below links.

.. [1] `Linux syscall categories <https://linasm.sourceforge.net/docs/syscalls/index.php>`_