# rm -rf build_lib build_apps

cmake -S . -B build_lib
cmake --build ./build_lib
cmake --install ./build_lib --prefix ./shaman_lib

cmake -S apps -B build_apps
cmake --build build_apps