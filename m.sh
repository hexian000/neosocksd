#!/bin/sh
# m.sh: in-tree build script for convenience
cd "$(dirname "$0")"
set -ex

# empty the build directory, preserving build/tmp (the scratch area that
# AGENTS.md documents as surviving clean rebuilds)
clean_build() {
    mkdir -p build
    find build -mindepth 1 -maxdepth 1 ! -name tmp -exec rm -rf {} +
}

case "$1" in
"fmt")
    # format code
    python3 scripts/format.py .
    ;;
"c")
    # clean artifacts
    clean_build
    rm -f compile_commands.json
    ;;
"doc")
    VERSION="dev"
    if git rev-parse --git-dir >/dev/null 2>&1; then
        # 2+ tags on HEAD means one line per tag; a raw embedded newline
        # would break the single-line sed replacement below.
        VERSION="$(git tag --points-at HEAD | tr '\n' ',')"
        VERSION="${VERSION%,}"
        if [ -z "${VERSION}" ]; then
            VERSION="git-$(git rev-parse --short HEAD)"
        fi
        if ! git diff --quiet HEAD --; then
            VERSION="${VERSION}+"
        fi
    fi
    mkdir -p build/doc
    cp -r neosocksd.lua libruleset.lua agent.lua example build/doc/
    VERSION_REPLACEMENT="$(printf '%s' "${VERSION}" | sed 's/[\\&/]/\\&/g')"
    sed "s/^Version: dev$/Version: ${VERSION_REPLACEMENT}/g" API.md >build/doc/API.md
    ;;
"x")
    # cross compiling, environment vars need to be set
    : "${SYSROOT:?SYSROOT must be set}"
    clean_build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_SYSROOT="${SYSROOT}" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DCMAKE_SKIP_RPATH=ON \
        ..
    cmake --build . -t neosocksd
    ls -lh bin/neosocksd
    ;;
"vanilla")
    # rebuild without ruleset
    clean_build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DENABLE_RULESET=OFF \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/neosocksd
    ;;
"posix")
    # rebuild for strict POSIX compliance
    clean_build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DFORCE_POSIX=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/neosocksd
    ;;
"clang")
    # rebuild with Linux clang/lld
    clean_build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld --rtlib=compiler-rt" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build . -t neosocksd
    (cd bin && llvm-objdump -drwS neosocksd >neosocksd.S)
    ls -lh bin/neosocksd
    ;;
"msys2")
    # rebuild with MSYS 2
    clean_build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc" \
        ..
    cmake --build . -t neosocksd
    HOST="$(cc -dumpmachine)"
    zip -9j "neosocksd-win32.${HOST}.zip" \
        "/usr/bin/msys-2.0.dll" \
        "/usr/bin/msys-cares-2.dll" \
        "bin/neosocksd.exe"
    ls -lh "neosocksd-win32.${HOST}.zip"
    ;;
"ndk")
    # rebuild with Android NDK
    : "${ANDROID_API_LEVEL:?ANDROID_API_LEVEL must be set}"
    : "${ANDROID_NDK_ROOT:?ANDROID_NDK_ROOT must be set}"
    : "${ABI_NAME:?ABI_NAME must be set}"
    clean_build && cd build
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
    cmake --build . -t neosocksd
    ls -lh bin/neosocksd
    ;;
"san")
    # rebuild with clang & sanitizers
    clean_build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DCMAKE_C_COMPILER="clang" \
        -DENABLE_SANITIZERS=ON \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/neosocksd
    ;;
"min")
    # rebuild for minimized size
    clean_build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="MinSizeRel" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        ..
    cmake --build . -t neosocksd
    ls -lh bin/neosocksd
    ;;
"p")
    # rebuild for profiling
    clean_build && cd build
    cmake \
        -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DENABLE_THREADS=ON \
        ..
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    (cd bin && objdump -drwS neosocksd >neosocksd.S)
    ls -lh bin/neosocksd
    ;;
"r")
    # rebuild for release
    clean_build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Release" \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/neosocksd
    ;;
"d")
    # rebuild for debug
    clean_build && cd build
    cmake \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE="Debug" \
        -DENABLE_SANITIZERS=ON \
        -DENABLE_THREADS=ON \
        ..
    cp compile_commands.json ../
    cmake --build . -j"$(nproc)"
    ctest -j"$(nproc)"
    ls -lh bin/neosocksd
    ;;
"")
    # incremental build
    mkdir -p build && cd build
    cmake .. && cmake --build .
    ls -lh bin/neosocksd
    ;;
*)
    echo "Unknown option: $1" >&2
    exit 1
    ;;
esac
