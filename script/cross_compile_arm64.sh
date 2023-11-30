export CXX_COMPILER=aarch64-linux-gnu-g++
export CC_COMPILER=aarch64-linux-gnu-gcc

cmake -S. -B build_arm64 -D CMAKE_C_COMPILER=$CC_COMPILER -D CMAKE_CXX_COMPILER=$CXX_COMPILER

cmake --build build_arm64 --target shaman --target test_prog
