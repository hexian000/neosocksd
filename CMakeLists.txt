cmake_minimum_required(VERSION 3.13)
project(neosocksd
    LANGUAGES C
    HOMEPAGE_URL "https://github.com/hexian000/neosocksd")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

function(get_git_version)
    find_package(Git)
    if(NOT GIT_FOUND)
        return()
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --git-dir
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        RESULT_VARIABLE RESULT
        OUTPUT_VARIABLE GIT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(RESULT)
        return()
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" tag --points-at HEAD
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if("${GIT_VERSION}" STREQUAL "")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
            OUTPUT_VARIABLE GIT_HEAD
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        set(GIT_VERSION "git-${GIT_HEAD}")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" diff --quiet HEAD --
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        RESULT_VARIABLE RESULT)
    if(RESULT)
        set(GIT_VERSION "${GIT_VERSION}+")
    endif()
    set(PROJECT_VERSION_STRING "${GIT_VERSION}" PARENT_SCOPE)
endfunction(get_git_version)

if("${PROJECT_VERSION_STRING}" STREQUAL "")
    set(PROJECT_VERSION_STRING "dev")
    get_git_version()
endif()
message(STATUS "Project version: ${PROJECT_VERSION_STRING}")

include(CTest)

option(ENABLE_SANITIZERS "Enable address, leak, undefined sanitizer" OFF)
option(BUILD_STATIC "Build a static executable" OFF)
option(BUILD_PIE "Build a position independent executable" OFF)
option(ENABLE_MIMALLOC "Enable mimalloc" OFF)
option(FORCE_POSIX "Build the core features using POSIX.1 APIs only" OFF)
option(LINK_STATIC_LIBS "Link against static libraries" OFF)
option(ENABLE_SYSTEMD "Enable systemd integration" OFF)
option(ENABLE_RULESET "Enable ruleset scripting (requires Lua)" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(BUILD_PIE)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffile-prefix-map=${PROJECT_SOURCE_DIR}/=")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s")
    set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} -s")
    if(ENABLE_SANITIZERS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,leak,undefined -fstack-protector-all")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address,leak,undefined -static-libasan -static-liblsan -static-libubsan")
    endif()
    if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
        set(CMAKE_C_COMPILE_OPTIONS_IPO -flto=1 -fno-fat-lto-objects -flto-partition=one -fuse-linker-plugin)
    endif()
    if(BUILD_STATIC AND BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-pie")
    elseif(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    elseif(CMAKE_POSITION_INDEPENDENT_CODE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    endif()
    if(NOT BUILD_STATIC AND LINK_STATIC_LIBS)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc")
    endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffile-compilation-dir=${PROJECT_SOURCE_DIR}")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s")
    set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} -s")
    if(ENABLE_SANITIZERS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,leak,undefined -fstack-protector-all")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address,leak,undefined -static-libsan")
    endif()
    if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
        set(CMAKE_C_COMPILE_OPTIONS_IPO -flto)
    endif()
    if(BUILD_STATIC AND BUILD_PIE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-pie")
    elseif(BUILD_STATIC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    elseif(CMAKE_POSITION_INDEPENDENT_CODE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    endif()
    if(NOT BUILD_STATIC AND LINK_STATIC_LIBS)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc")
    endif()
endif()

if(FORCE_POSIX)
    message(STATUS "POSIX-compliant system: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
else()
    message(STATUS "Unix-like system: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
endif()

add_subdirectory(contrib)
add_subdirectory(src)
