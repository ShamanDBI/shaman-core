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


Example #1 : Syscall Tracer
===========================

.. code-block:: console

    cmake -S ./examples/syscall_tracer -B ./builds/syscall_tracer
    cmake --build ./builds/syscall_tracer


Example #2 : Binary Code Coverage
=================================


.. code-block:: console

    cmake -S ./examples/binary_coverage -B ./builds/binary_coverage_app
    cmake --build ./builds/binary_coverage_app

    cmake -S ./examples/binary_coverage -B ./builds/binary_coverage_consumer
    cmake --build ./builds/binary_coverage_consumer


Running
-------

#. You first need to start target application

    .. code-block:: console

        builds/binary_coverage -l app.log --cov-basic-block ./test_prog_1.bb --pipe-id 51966 -e ./test_target/bin/test_target 1
#. Then start another terminal which has the coverage consume application with the following command.

    .. code-block:: console
        
        # starts the binary consumer
        builds/binary_coverage_consumer/binary_coverage_consumer