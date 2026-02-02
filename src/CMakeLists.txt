add_executable(neosocksd
    util.c util.h
    conf.c conf.h
    sockutil.c sockutil.h
    dialer.c dialer.h
    resolver.c resolver.h
    codec.c codec.h
    ruleset.c ruleset.h
    transfer.c transfer.h
    forward.c forward.h
    socks.c socks.h
    httputil.c httputil.h
    http_proxy.c http_proxy.h
    api_server.c api_server.h
    api_client.c api_client.h
    server.c server.h
    main.c
)
add_subdirectory(proto)
target_include_directories(neosocksd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(neosocksd PRIVATE csnippets miniz)

if(FORCE_POSIX)
    target_compile_definitions(neosocksd PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(neosocksd PRIVATE _GNU_SOURCE)
endif()

include(CheckSymbolExists)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(pipe2 "unistd.h" HAVE_PIPE2)
check_symbol_exists(splice "fcntl.h" HAVE_SPLICE)
check_symbol_exists(IP_TRANSPARENT "netinet/in.h" HAVE_IP_TRANSPARENT)
check_symbol_exists(SO_BINDTODEVICE "sys/socket.h" HAVE_SO_BINDTODEVICE)
check_symbol_exists(SO_REUSEPORT "sys/socket.h" HAVE_SO_REUSEPORT)
check_symbol_exists(TCP_FASTOPEN "netinet/tcp.h" HAVE_TCP_FASTOPEN)
check_symbol_exists(TCP_FASTOPEN_CONNECT "netinet/tcp.h" HAVE_TCP_FASTOPEN_CONNECT)

if(NOT FORCE_POSIX)
    if(HAVE_PIPE2 AND HAVE_SPLICE)
        set(WITH_SPLICE TRUE)
    endif()
    if(HAVE_IP_TRANSPARENT)
        set(WITH_TPROXY TRUE)
    endif()
    if(HAVE_SO_BINDTODEVICE)
        set(WITH_NETDEVICE TRUE)
    endif()
    if(HAVE_SO_REUSEPORT)
        set(WITH_REUSEPORT TRUE)
    endif()
    if(HAVE_TCP_FASTOPEN)
        set(WITH_TCP_FASTOPEN TRUE)
    endif()
    if(HAVE_TCP_FASTOPEN_CONNECT)
        set(WITH_TCP_FASTOPEN_CONNECT TRUE)
    endif()
endif()

target_compile_options(neosocksd PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
# be strict with original sources
target_compile_options(neosocksd PRIVATE -pedantic -Wall -Wextra -Werror)

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if(EXISTS "${LIBEV_INCLUDE_DIR}/ev.h")
    file(READ "${LIBEV_INCLUDE_DIR}/ev.h" LIBEV_VERSION_STR)
    string(REGEX MATCH "#define EV_VERSION_MAJOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define EV_VERSION_MINOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MINOR ${CMAKE_MATCH_1})
    set(LIBEV_VERSION "${EV_VERSION_MAJOR}.${EV_VERSION_MINOR}")
endif()
if((NOT ${LIBEV_VERSION} VERSION_GREATER_EQUAL "4.31") OR (NOT EXISTS ${LIBEV_LIBRARY}))
    message(FATAL_ERROR "libev (>= 4.31) not found")
endif()
message(STATUS "libev ${LIBEV_VERSION}: ${LIBEV_LIBRARY}")
target_include_directories(neosocksd SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LIBEV_LIBRARY})

# find c-ares
find_path(LIBCARES_INCLUDE_DIR NAMES ares.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBCARES_LIBRARY NAMES libcares_static.a libcares.a)
else()
    find_library(LIBCARES_LIBRARY NAMES cares)
endif()
if(EXISTS "${LIBCARES_INCLUDE_DIR}/ares_version.h")
    file(READ "${LIBCARES_INCLUDE_DIR}/ares_version.h" LIBCARES_VERSION_STR)
    string(REGEX MATCH "#define ARES_VERSION_STR[ \t]+\"([^\n]*)\"" _ ${LIBCARES_VERSION_STR})
    set(LIBCARES_VERSION ${CMAKE_MATCH_1})
endif()
if((NOT ${LIBCARES_VERSION} VERSION_GREATER_EQUAL "1.16.0") OR (NOT EXISTS ${LIBCARES_LIBRARY}))
    message(WARNING "c-ares (>= 1.16.0) not found, asynchronous name resolution is unavailable")
else()
    message(STATUS "c-ares ${LIBCARES_VERSION}: ${LIBCARES_LIBRARY}")
    set(WITH_CARES TRUE)
endif()

if(WITH_CARES)
    target_include_directories(neosocksd SYSTEM PRIVATE ${LIBCARES_INCLUDE_DIR})
    target_link_libraries(neosocksd PRIVATE ${LIBCARES_LIBRARY})
endif()

# find lua
find_path(LUA_INCLUDE_DIR
    NAMES luaconf.h lua.h lualib.h lauxlib.h
    PATH_SUFFIXES
    lua55 lua5.5 lua-5.5
    lua54 lua5.4 lua-5.4
    lua53 lua5.3 lua-5.3
    lua
)
find_library(LUA_LIBRARY
    NAMES
    liblua55.a liblua5.5.a liblua-5.5.a
    liblua54.a liblua5.4.a liblua-5.4.a
    liblua53.a liblua5.3.a liblua-5.3.a
    liblua.a
    PATH_SUFFIXES
    lua55 lua5.5 lua-5.5
    lua54 lua5.4 lua-5.4
    lua53 lua5.3 lua-5.3
    lua
)
if((NOT EXISTS ${LUA_LIBRARY}) AND (NOT BUILD_STATIC))
    find_library(LUA_LIBRARY
        NAMES
        lua55 lua5.5 lua-5.5
        lua54 lua5.4 lua-5.4
        lua53 lua5.3 lua-5.3
        lua
        PATH_SUFFIXES
        lua55 lua5.5 lua-5.5
        lua54 lua5.4 lua-5.4
        lua53 lua5.3 lua-5.3
        lua
    )
endif()
if((EXISTS "${LUA_INCLUDE_DIR}/lua.h") AND (EXISTS ${LUA_LIBRARY}))
    set(WITH_LUA TRUE)
endif()

if(ENABLE_RULESET)
    if(NOT WITH_LUA)
        message(FATAL_ERROR "Lua not found, ruleset is not available")
    endif()
    message(STATUS "Lua: ${LUA_LIBRARY}")
    set(WITH_RULESET TRUE)
    target_include_directories(neosocksd SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
    target_link_libraries(neosocksd PRIVATE ${LUA_LIBRARY} ${CMAKE_DL_LIBS})
    add_subdirectory(ruleset)
endif()

# find systemd
if(ENABLE_SYSTEMD)
    find_path(SYSTEMD_INCLUDE_DIR NAMES systemd/sd-daemon.h)
    find_library(SYSTEMD_LIBRARY NAMES systemd)
    if((EXISTS ${SYSTEMD_INCLUDE_DIR}) AND (EXISTS ${SYSTEMD_LIBRARY}))
        message(STATUS "systemd: ${SYSTEMD_LIBRARY}")
        set(WITH_SYSTEMD TRUE)
        target_include_directories(neosocksd SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIR})
        target_link_libraries(neosocksd PRIVATE ${SYSTEMD_LIBRARY})
    else()
        message(WARNING "systemd not found")
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(WITH_CRASH_HANDLER TRUE)
endif()

if(ENABLE_MIMALLOC)
    find_package(mimalloc)
    if(EXISTS "${MIMALLOC_OBJECT_DIR}/mimalloc.o")
        message(STATUS "mimalloc ${mimalloc_VERSION}: ${MIMALLOC_OBJECT_DIR}/mimalloc.o")
        target_link_libraries(neosocksd PUBLIC "${MIMALLOC_OBJECT_DIR}/mimalloc.o")
    else()
        message(WARNING "mimalloc not found")
    endif()
endif()

include(CheckLibraryExists)
check_library_exists(m ldexp "" LIBM)
if(LIBM)
    target_link_libraries(neosocksd PRIVATE m)
endif()

install(TARGETS neosocksd DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
configure_file(version.c.in version.c ESCAPE_QUOTES)

target_sources(neosocksd
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)
