#!/bin/sh
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
NPROC=""
if command -v nproc >/dev/null 2>&1; then
    NPROC="$(nproc --all)"
fi
set -ex

case "$1" in
"x")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/src/neosocksd"
    ;;
"xs")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DBUILD_STATIC=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/src/neosocksd"
    ;;
"r")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/src/neosocksd"
    ;;
"s")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DBUILD_STATIC=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/src/neosocksd"
    ;;
"p")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    (cd "build/src" && objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/src/neosocksd"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -DPOSIX=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/src/neosocksd"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    (cd "build/src" && llvm-objdump -drwS "neosocksd" >"neosocksd.S")
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
    nice cmake --build "build" --parallel "${NPROC}"
    # cd "build/src/tests" && ctest
    ls -lh "build/src/neosocksd"
    ;;
esac
