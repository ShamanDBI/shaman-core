export CXX_COMPILER=/home/hussain/pdev/linux-exp/src/buildroot/output/host/bin/arm-buildroot-linux-gnueabi-g++
export CC_COMPILER=/home/hussain/pdev/linux-exp/src/buildroot/output/host/bin/arm-buildroot-linux-gnueabi-gcc

cmake -S. -B build_arm -D CMAKE_C_COMPILER=$CC_COMPILER -D CMAKE_CXX_COMPILER=$CXX_COMPILER

cmake --build build_arm --target shaman --target test_prog
