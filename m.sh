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
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"xs")
    # cross compiling, environment vars need to be set
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSTEM_NAME="Linux" \
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DBUILD_STATIC=ON \
        -DENABLE_JEMALLOC=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"r")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"s")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DBUILD_STATIC=ON \
        -DENABLE_JEMALLOC=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"p")
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    (cd "build/bin" && objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/bin/neosocksd"
    ;;
"min")
    # rebuild for minimized size
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DENABLE_RULESET=OFF \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"posix")
    # force POSIX APIs
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"clang")
    # rebuild with Linux clang/lld
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build"
    (cd "build/bin" && llvm-objdump -drwS "neosocksd" >"neosocksd.S")
    ls -lh "build/bin/neosocksd"
    ;;
"msys2")
    rm -rf "build" && mkdir "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DENABLE_LTO=OFF \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        -S "." -B "build"
    nice cmake --build "build"
    HOST="$(cc -dumpmachine)"
    zip -9j "build/neosocksd-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "/usr/bin/msys-cares-2.dll" \
        "build/bin/neosocksd.exe"
    ls -lh "build/neosocksd-win32.${HOST}.zip"
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
        -DCMAKE_FIND_ROOT_PATH="${SYSROOT};${LIBROOT}" \
        -DLINK_STATIC_LIBS=ON \
        -S "." -B "build"
    nice cmake --build "build"
    ls -lh "build/bin/neosocksd"
    ;;
"d")
    if command -v clang-format >/dev/null; then
        find src -type f -regex '.*\.[hc]' -exec clang-format -i {} +
    fi
    # debug
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    ln -sf build/compile_commands.json compile_commands.json
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
"san")
    # rebuild with clang & sanitizers
    rm -rf "build" && mkdir -p "build"
    cmake -G "${GENERATOR}" \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -S . -B "build"
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
"c")
    rm -rf "build" "compile_commands.json"
    ;;
*)
    nice cmake --build "build" --parallel
    ls -lh "build/bin/neosocksd"
    ;;
esac
