#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/src/neosocksd"
    ;;
"xs")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DBUILD_STATIC=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/src/neosocksd"
    ;;
"r")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/src/neosocksd"
    ;;
"s")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DBUILD_STATIC=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/src/neosocksd"
    ;;
"p")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build"
    (cd "build/src" && objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/src/neosocksd"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DTARGET_POSIX=1 \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/src/neosocksd"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -S . -B "build"
    nice cmake --build "build"
    (cd "build/src" && llvm-objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/src/neosocksd"
    ;;
"msys2")
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        -DLINK_STATIC_LIBS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    TARGET="$(cc -dumpmachine)"
    zip -9j "build/neosocksd-win32.${TARGET}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "build/src/neosocksd.exe"
    ls -lh "build/neosocksd-win32.${TARGET}.zip"
    ;;
"ndk")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_ANDROID_NDK="${NDK}" \
        -DCMAKE_SYSTEM_NAME="Android" \
        -DCMAKE_SYSTEM_VERSION="${API}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/src/kcptun-libev"
    ;;
"asan")
    # rebuild with asan
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    ls -lh "build/src/neosocksd"
    ;;
"clang-asan")
    # rebuild with clang & asan
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/src/neosocksd"
    ;;
"c")
    rm -rf "build" "compile_commands.json"
    ;;
*)
    mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    # cd "build/src/tests" && ctest
    ls -lh "build/src/neosocksd"
    ;;
esac
