mkdir -p builds

cmake -S . -B builds/build_lib
cmake --build ./builds/build_lib
cmake --install ./builds/build_lib --prefix ./builds/shaman_lib

cmake -S . -B ./builds/test_target
cmake --build ./builds/test_target

cmake -S ./examples/syscall_tracer -B ./builds/syscall_tracer
cmake --build ./builds/syscall_tracer

cmake -S ./examples/binary_coverage -B ./builds/binary_coverage_app
cmake --build ./builds/binary_coverage_app
