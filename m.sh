#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
GENERATOR="Unix Makefiles"
NPROC=1
set -ex

case "$1" in
"c")
    # clean artifacts
    rm -rf "build" "compile_commands.json"
    ;;
"x")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/bin/neosocksd"
    ;;
"posix")
    # rebuild for strict POSIX compliance
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/bin/neosocksd"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    (cd "build/bin" && llvm-objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/bin/neosocksd"
    ;;
"msys2")
    # rebuild with MSYS 2
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        -S "." -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    HOST="$(cc -dumpmachine)"
    zip -9j "build/neosocksd-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "/usr/bin/msys-cares-2.dll" \
        "build/bin/neosocksd.exe"
    ls -lh "build/neosocksd-win32.${HOST}.zip"
    ;;
"ndk")
    # rebuild with Android NDK
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_ANDROID_NDK="${ANDROID_NDK_ROOT}" \
        -DCMAKE_SYSTEM_NAME="Android" \
        -DCMAKE_SYSTEM_VERSION="${ANDROID_API_LEVEL}" \
        -DCMAKE_ANDROID_ARCH_ABI="${ABI_NAME}" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_MIMALLOC=ON \
        -DLINK_STATIC_LIBS=ON \
        -S "." -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/bin/neosocksd"
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
"min")
    # rebuild for minimized size
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_RULESET=OFF \
        -S "." -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/bin/neosocksd"
    ;;
"p")
    # rebuild for profiling
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    (cd "build/bin" && objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/bin/neosocksd"
    ;;
"r")
    # rebuild for release
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel "${NPROC}"
    ls -lh "build/bin/neosocksd"
    ;;
"d")
    # rebuild for debug
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
*)
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
esac
