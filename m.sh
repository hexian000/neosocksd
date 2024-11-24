#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
set -ex

case "$1" in
"c")
    # clean artifacts
    rm -rf build compile_commands.json
    ;;
"x")
    # cross compiling, environment vars need to be set
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSROOT="${SYSROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DCMAKE_SKIP_RPATH=ON \
        ..
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"posix")
    # rebuild for strict POSIX compliance
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    (cd bin && llvm-objdump -drwS neosocksd >neosocksd.S)
    ls -lh bin/neosocksd
    ;;
"msys2")
    # rebuild with MSYS 2
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        ..
    cmake --build .
    HOST="$(cc -dumpmachine)"
    zip -9j "neosocksd-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "/usr/bin/msys-cares-2.dll" \
        "bin/neosocksd.exe"
    ls -lh "neosocksd-win32.${HOST}.zip"
    ;;
"ndk")
    # rebuild with Android NDK
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Android" \
        -DCMAKE_SYSTEM_VERSION="${ANDROID_API_LEVEL}" \
        -DCMAKE_ANDROID_NDK="${ANDROID_NDK_ROOT}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI_NAME}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_MIMALLOC=ON \
        -DLINK_STATIC_LIBS=ON \
        ..
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"min")
    # rebuild for minimized size
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"p")
    # rebuild for profiling
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build .
    (cd bin && objdump -drwS neosocksd >neosocksd.S)
    ls -lh bin/neosocksd
    ;;
"r")
    # rebuild for release
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/neosocksd
    ;;
"d")
    # rebuild for debug
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    rm -rf build && mkdir -p build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        ..
    cp compile_commands.json ../
    cmake --build .
    ls -lh bin/neosocksd
    ;;
*)
    cd build
    cmake --build .
    ls -lh bin/neosocksd
    ;;
esac
