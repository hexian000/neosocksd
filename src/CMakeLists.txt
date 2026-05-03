add_executable(neosocksd
    util.c util.h
    conf.c conf.h
    dialer.c dialer.h
    resolver.c resolver.h
    ruleset.c ruleset.h
    transfer.c transfer.h
    http_client.c http_client.h
    forward.c forward.h
    socks.c socks.h
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

if(WITH_LUA)
    message(STATUS "Lua: ${LUA_LIBRARY}")
    target_include_directories(neosocksd SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
    target_link_libraries(neosocksd PRIVATE ${LUA_LIBRARY} ${CMAKE_DL_LIBS})
endif()

if(ENABLE_RULESET)
    if(NOT WITH_LUA)
        message(FATAL_ERROR "Lua not found, ruleset is not available")
    endif()
    set(WITH_RULESET TRUE)
endif()

if(WITH_THREADS)
    target_link_libraries(neosocksd PRIVATE Threads::Threads)
endif()

if(LIBM)
    target_link_libraries(neosocksd PRIVATE m)
endif()

# =============================================================================
# add_unit_test: register a test executable with standard compile settings.
#
# Arguments:
#   SRCS            source file list
#   CONFIG_H        path to generated config.h
#                   (default: ${CMAKE_CURRENT_BINARY_DIR}/config.h)
#   NO_LIBEV        flag: do not link libev
#   WITH_LUA        flag: link Lua when WITH_LUA is set
#   WITH_RULESET    flag: link Lua when WITH_RULESET is set
#   WITH_THREADS    flag: link Threads::Threads when WITH_THREADS is set
#   WITH_CARES      flag: link c-ares when WITH_CARES is set
#   EXTRA_INCLUDES  list of additional private include directories
# =============================================================================
function(add_unit_test TEST_NAME)
    cmake_parse_arguments(
        UT
        "NO_LIBEV;WITH_LUA;WITH_RULESET;WITH_THREADS;WITH_CARES"
        "CONFIG_H"
        "SRCS;EXTRA_INCLUDES"
        ${ARGN}
    )
    if(NOT UT_CONFIG_H)
        set(UT_CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/config.h")
    endif()
    add_executable(${TEST_NAME} ${UT_SRCS})
    target_include_directories(${TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(UT_EXTRA_INCLUDES)
        target_include_directories(${TEST_NAME} PRIVATE ${UT_EXTRA_INCLUDES})
    endif()
    target_compile_options(${TEST_NAME} PRIVATE "-include${UT_CONFIG_H}")
    target_compile_options(${TEST_NAME} PRIVATE -pedantic -Wall -Wextra -Werror)
    target_link_libraries(${TEST_NAME} PRIVATE csnippets miniz)
    if(NOT UT_NO_LIBEV)
        target_link_libraries(${TEST_NAME} PRIVATE ${LIBEV_LIBRARY})
    endif()
    if(UT_WITH_LUA AND WITH_LUA)
        target_include_directories(${TEST_NAME} SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
        target_link_libraries(${TEST_NAME} PRIVATE ${LUA_LIBRARY} ${CMAKE_DL_LIBS})
    endif()
    if(UT_WITH_RULESET AND WITH_RULESET)
        target_include_directories(${TEST_NAME} SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
        target_link_libraries(${TEST_NAME} PRIVATE ${LUA_LIBRARY} ${CMAKE_DL_LIBS})
    endif()
    if(UT_WITH_THREADS AND WITH_THREADS)
        target_link_libraries(${TEST_NAME} PRIVATE Threads::Threads)
    endif()
    if(UT_WITH_CARES AND WITH_CARES)
        target_include_directories(${TEST_NAME} SYSTEM PRIVATE ${LIBCARES_INCLUDE_DIR})
        target_link_libraries(${TEST_NAME} PRIVATE ${LIBCARES_LIBRARY})
    endif()
    if(LIBM)
        target_link_libraries(${TEST_NAME} PRIVATE m)
    endif()
    if(FORCE_POSIX)
        target_compile_definitions(${TEST_NAME} PRIVATE _POSIX_C_SOURCE=200809L)
    else()
        target_compile_definitions(${TEST_NAME} PRIVATE _GNU_SOURCE)
    endif()
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

if(ENABLE_RULESET)
    add_subdirectory(ruleset)
endif()

if(ENABLE_MIMALLOC)
    find_package(mimalloc)
    if(EXISTS "${MIMALLOC_OBJECT_DIR}/mimalloc.o")
        message(STATUS "mimalloc ${mimalloc_VERSION}: ${MIMALLOC_OBJECT_DIR}/mimalloc.o")
        target_link_libraries(neosocksd PRIVATE "${MIMALLOC_OBJECT_DIR}/mimalloc.o")
    else()
        message(WARNING "mimalloc not found")
    endif()
endif()

install(TARGETS neosocksd DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
configure_file(version.c.in version.c ESCAPE_QUOTES)

target_sources(neosocksd
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)

# =============================================================================
# tests
# =============================================================================

if(WITH_RULESET)
    add_unit_test(socks_test
        SRCS socks_test.c socks.c)
    add_unit_test(http_proxy_test
        SRCS http_proxy_test.c http_proxy.c proto/http.c proto/codec.c)
    add_unit_test(api_server_test
        SRCS api_server_test.c api_server.c proto/http.c proto/codec.c
             "${CMAKE_CURRENT_BINARY_DIR}/version.c")
    add_unit_test(api_client_test
        SRCS api_client_test.c api_client.c http_client.c
             proto/http.c proto/codec.c)
endif()

add_unit_test(forward_test
    SRCS forward_test.c forward.c)
add_unit_test(conf_test
    SRCS conf_test.c conf.c "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    WITH_LUA)
add_unit_test(transfer_test
    SRCS transfer_test.c transfer.c
    WITH_THREADS)
add_unit_test(server_test
    SRCS server_test.c server.c conf.c "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    WITH_LUA)
add_unit_test(http_test
    SRCS proto/http_test.c proto/http.c proto/codec.c)
add_unit_test(codec_test
    SRCS proto/codec_test.c proto/codec.c)
add_unit_test(dialer_test
    SRCS dialer_test.c dialer.c util.c resolver.c
         server.c server.h socks.c socks.h http_proxy.c http_proxy.h
         transfer.c transfer.h proto/http.c proto/http.h proto/codec.c proto/codec.h
         "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    WITH_RULESET WITH_THREADS WITH_CARES)
add_unit_test(resolver_test
    SRCS resolver_test.c resolver.c
    WITH_CARES)
add_unit_test(util_test
    SRCS util_test.c util.c "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    WITH_RULESET WITH_CARES)
add_unit_test(http_client_test
    SRCS http_client_test.c http_client.c proto/http.c proto/codec.c)

if(WITH_LUA)
    add_unit_test(regex_test
        SRCS ruleset/regex_test.c ruleset/regex.c
        NO_LIBEV WITH_LUA)
    add_unit_test(time_test
        SRCS ruleset/time_test.c ruleset/time.c
        NO_LIBEV WITH_LUA)
    add_unit_test(base_test
        SRCS ruleset/base_test.c ruleset/base.c util.c dialer.c resolver.c
             "${CMAKE_CURRENT_BINARY_DIR}/version.c"
        WITH_LUA WITH_CARES)
    add_unit_test(marshal_test
        SRCS ruleset/marshal_test.c ruleset/marshal.c ruleset/base.c
             util.c dialer.c resolver.c
             "${CMAKE_CURRENT_BINARY_DIR}/version.c"
        WITH_LUA WITH_CARES)
    add_unit_test(zlib_test
        SRCS ruleset/zlib_test.c ruleset/zlib.c ruleset/base.c
             proto/codec.c util.c dialer.c resolver.c
             "${CMAKE_CURRENT_BINARY_DIR}/version.c"
        WITH_LUA WITH_CARES)
    add_unit_test(ruleset_test
        SRCS ruleset_test.c ruleset.c ruleset/base.c ruleset/cfunc.c
        WITH_LUA)
endif()
