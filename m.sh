#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf xbuild
    mkdir -p "xbuild" && cd "xbuild"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    ls -lh src/neosocksd
    ;;
"xs")
    # cross compiling, environment vars need to be set
    rm -rf xbuild
    mkdir -p "xbuild" && cd "xbuild"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DLINK_STATIC_LIBS=TRUE \
        ..
    cmake --build . --parallel
    ls -lh src/neosocksd
    ;;
"r")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    ls -lh src/neosocksd
    ;;
"s")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DLINK_STATIC_LIBS=TRUE \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    ls -lh src/neosocksd
    ;;
"p")
    rm -rf build
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    # cd src/tests && ctest
    cd src
    objdump -drwS neosocksd >neosocksd.S
    ls -lh neosocksd
    ;;
"posix")
    # force POSIX APIs
    rm -rf build
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DPOSIX=1 \
        ..
    cmake --build . --parallel
    ls -lh src/neosocksd
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf build
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    cmake --build . --parallel
    cd src
    llvm-objdump -drwS neosocksd >neosocksd.S
    ls -lh neosocksd
    ;;
"c")
    rm -rf build xbuild
    ;;
*)
    mkdir -p build && cd build
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        ..
    ln -sf compile_commands.json ../compile_commands.json
    cmake --build . --parallel
    # cd src/tests && ctest
    ls -lh src/neosocksd
    ;;
esac
