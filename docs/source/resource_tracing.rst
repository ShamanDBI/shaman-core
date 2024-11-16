================
Resource Tracing
================

What is a Resource?
===================

System call(syscall) is interface the kernel provides to user-space to request for services. These services are abstraction for the complexity of hardware and software resources and provide a consistent interface to interact with these resources. *Software Resource* can be classified into different categories like file, network, inter-process communication(IPC), etc.

Kernel provides syscall to manipulate these software resources for example, *Sockets* can be create using *socket* syscall, once you have created the socket you can send and recieve data over the network using syscalls like sendto, sendmsg, recvfrom, recvmsg, etc and once you are done with communication you can close the socket using *close* syscall. Similarly kernel provides interface for *Files*, you can create file with *open* system call and then you can read and write data to file using *read* and *write* syscall and once done you can close the file with *close* syscall. 

This is just an over simplification but you should get an idea *what is a Resource*. There are six/seven categories of resource which is File, Socket, IPC, Process & Thread, Signals, Synchronization, System Identifiers, Device Drivers, and Time related, etc [1]_. Each syscall will belong to either one or more of this category. For example *read syscall* belongs to File and Socket. These are by no means and concrete classification but these abstraction can be encountered in almost any POSIX-compatible operating systems.

.. _resource-ccr:

Resource Life-cycle
===================

Let me explain the typical lifecycle states that a *software resource* goes through in an OS kernel:

1. **Create**: At this stage a resource is created like socket, spawning new process or create new file or an existing one is opened like file from the disk for example File. A unique resource identifier/handler is returned by the syscall at this stage. If you are interested in tracing it you can record the identifier and used it in sub-sequent stage.
2. **Consume**: At this staget resource is manipulated, configured or queried upon by operation like read, write, IOCTL syscall call using the unique identifier/handler returned form previous stage.
3. **Release**: Once done with the resource it is destroyed with syscall like *close*. This unique identifier/handle is surrendered to the OS kernel which can be may re-used the same identifier for new resource.

We will refere to this flow as *create-consume-release* in the future.

Each Resource has a unique identifier value when created, this value is passed as parameter to the sub-sequent syscalls while operating on it. Speaking for Unix-like OS the *Resource* a unique identifier is called as *file descritor*, in Windows they calls it as Handler/Objects. 

Not every syscall has such life-cycle, for example time related syscall simply return the current time of the system, nothing fancy happening here!


When to Use it?
===============

Often while reversing you are interested in tracking the data coming in and out of the system this is usually happens via File, Sockets of IPC. Syscall tracing can help you with this task, but practically speaking you can not tracing all the network socket or files because process will open lot of them which are unrelated to your task at hand. While you are reversing you are laser focus on one network socket data and its execution in the binary. So, what you are really interested in is all the system call which are made for read/writing to particular socket file descriptor. So, If you are reversing server binary you are interested in new client connect to server ports and what data is exchanged with the client. Or, if you are reversing client binary you are interesting in tracing data which is exchange on particular port. This exactly what resource tracing can help you to achieve.

Resource Tracing gives you an interface for tracing different Resource a Process uses. The interface exposes life-cycle method of resource. A resource Life-cycle includes creation of resource manipulation and closing of resource. This method of tracing give you access to different granility of Reverse Engineering. Tracing Individual System Call is a make sense when you want to take decision soley on the syscall for example getting time from Kernel.

But when you want to doing Attack surface enumeration you want to Trace the data coming and going out of the system you not looking at the indiviual System calls you focus is on the System Resource, like Data coming from Network is exposing you application to remote attacks, IPC resource is exposing your Process to other running Processes in the System, File Resource is exposing to the untrusted data from the file system that any user can write on the system. Similar argument can be made for Reverse Engineering Data recieved on the Network socket or reading from the File format reversing.

While Resource Interface is give you option trace all the Resource in the system but thats not practical and that will would generate over-welming amount of data to process, and you might be only interested in tracing specific Resource, like specific client socket or Particular File on file system. Resource Tracing API provides you `onFilter` function give you a peek al the File Create or Open system call based on the syscall you can decide if you are interested in tracing, to implement your logic which will decide you are interesting in trace the Resource. If `onFilter` function return true the the Resource which is create will added to list of actively traced Resource. Actively Tracing Resource means we are interested in every transaction done on that Resource which mean through Resource Interface you will get callback on every System Call.

Different types of Resource provide different type of callbacks. For example for File Operation you will get callback for Open, Read, Write, Close, etc. You can explore the details of the Interface on FileOperationTracer. Similary Network Sockets exposes some what similar callback, apart from callbacks for Open, Read, Write and Close. Network Resource different from file, A process can create Server Socket will is accepting Client connections and each client get its individual File Descriptor and returning True will only trace that Client Socket. While on the Client side, client might be creating socket connection to different Servers you might be interested in one connection. The traceing is automatically removed when the resource is closed.

The following set of interface provide you the ability to register a callback whenever a Process is attempting to creating a new Resource and give you a chance to peek at the parameter and decide if you are intereted in Tracing the entire life-cycle *create-consume-release* of the Resource. At present we have support for Network(NetworkOperationTracer) and file operation(FileOperationTracer) more will be added soon.

Keep in Mind
============

Is is just a glorified system call handling

Usage Guide
===========

`ResourceTracer` provides an callback interface to trace the life-cycle of Resource which we just discussed.

1. **Create**: All the System Call falling is this category invoke `onFilter` to decide if the Resoure has to be traced throught it lifecyle. This is case `onOpen` lifecycle method is called.
2. **Consume**: Based on type of resource all the system Call have a callback method.
3. **Release**: Since the Resource we are tracing no long exist tracing after this point is not done. For this case `onClose` callback is invoked.

Reference
=========

Some intereseting piece of reading you can do on this subject from below links.

.. [1] `Linux syscall categories <https://linasm.sourceforge.net/docs/syscalls/index.php>`_