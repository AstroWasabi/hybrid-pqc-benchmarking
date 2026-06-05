#Pre-Requisites

1. git
2. cmake
3. python3
4. gcc/clang


#Install liboqs-python (will install liboqs automatically and then install the wrapper)
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
cmake --build liboqs/build --target install
