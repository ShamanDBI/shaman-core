========
Building
========

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
