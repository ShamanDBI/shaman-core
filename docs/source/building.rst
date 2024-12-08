========
Building
========

This project is divided into two parts, the core library which has all the core features. To integerate this in your project you need to first build the code library which is show in the next section.

You can also refer to the scripts/build.sh file.

Building Core Library
=====================

.. code-block:: console

    mkdir -p builds
    cmake -S . -B builds/build_lib
    cmake --build ./builds/build_lib
    cmake --install ./builds/build_lib --prefix ./builds/shaman_lib

.. _example_systrace:

Example #1 : Syscall Tracer
===========================

This exmaple demonstrates different syscall related API's which the project offers and how to use them.

.. code-block:: console

    cmake -S ./examples/syscall_tracer -B ./builds/syscall_tracer
    cmake --build ./builds/syscall_tracer

.. _example_code_cov:

Example #2 : Binary Code Coverage
=================================

This project demonstrates how to collect binary code coverage. The trick is very simple, just place breakpoint every basic block of the module which you want to trace. Address of all the basic block is identified using Ghidra scripts.

This application also demonstrates another interseting concept. The is a shared memory between a consume and the producer process. The debugger is a the producer process which is spitting out the execution trace continuesly in the shared memory. And then there is the consumer process which is another process which is listening on the shared buffer and processing this coverage. This design is inspired from this blog.

The reason for having such design is the speed and extensibility. Writing to memory is waay.. fast then dumping the data to the file. Let the writing of file be done by another process and collect of coverage should not be slowed but it. You can also send this data over the socket if you are running this in an IoT device where memory is a big constrain and you want to collect huge traces. 

Build
-----

This application will produce two binaries *binary_coverage_app* and *binary_coverage_consumer* in *./builds/binary_coverage_app* directory.

.. code-block:: console

    mkdir builds

    cmake -S ./examples/binary_coverage -B ./builds/binary_coverage_app
    cmake --build ./builds/binary_coverage_app

Running
-------

#. First extract the basic block address of module you are interested to trace using Ghidra script.

    .. code-block:: console

        # $GHIDRA_HOME   - path to the ghidra home directory
        # target_binary  - application binary for which you want to generate gather code coverage
        # project output - project file created by ghidra will be saved in this directory
        # project name   - name of the project in ghidra
        # script_path    - path which has all the ghidra scripts, you can set this value to <shaman_dir>/script
        # action         - if you running the binary for the first time 
        $GHIDRA_HOME/support/analyzeHeadless <project output> <project_name> -[action] <target_binary> -scriptPath <script_path> -postscript ghidra_bb_expoter.py

#. You first need to start target application

    .. code-block:: console

        builds/binary_coverage_app/binary_coverage -l app.log --cov-basic-block ./test_prog_1.bb --pipe-id 51966 -e ./test_target/bin/test_target 1

#. Then start another terminal which has the coverage consume application with the following command.

    .. code-block:: console
        
        # starts the binary consumer
        builds/binary_coverage_app/binary_coverage_consumer