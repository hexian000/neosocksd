add_executable(neosocksd
    util.c util.h
    conf.c conf.h
    sockutil.c sockutil.h
    dialer.c dialer.h
    resolver.c resolver.h
    codec.c codec.h
    ruleset.c ruleset.h
    transfer.c transfer.h
    session.c session.h
    forward.c forward.h
    socks.c socks.h
    http_parser.c http_parser.h
    http_server.c http_server.h http_client.c http_client.h
    http_proxy.c http_api.c http.h
    server.c server.h
    main.c
)
target_link_libraries(neosocksd PRIVATE csnippets miniz)

if(NOT TARGET_POSIX AND (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android"))
    target_compile_definitions(neosocksd PRIVATE _GNU_SOURCE)
else()
    target_compile_definitions(neosocksd PRIVATE _POSIX_C_SOURCE=200809L)
endif()

include(CheckSymbolExists)
check_symbol_exists(IP_TRANSPARENT "netinet/in.h" HAVE_IP_TRANSPARENT)
check_symbol_exists(SO_BINDTODEVICE "sys/socket.h" HAVE_SO_BINDTODEVICE)
check_symbol_exists(SO_REUSEPORT "sys/socket.h" HAVE_SO_REUSEPORT)
check_symbol_exists(TCP_FASTOPEN "netinet/tcp.h" HAVE_TCP_FASTOPEN)

if(NOT TARGET_POSIX AND HAVE_IP_TRANSPARENT)
    set(WITH_TPROXY TRUE)
endif()
if(NOT TARGET_POSIX AND HAVE_SO_BINDTODEVICE)
    set(WITH_NETDEVICE TRUE)
endif()
if(NOT TARGET_POSIX AND HAVE_SO_REUSEPORT)
    set(WITH_REUSEPORT TRUE)
endif()
if(NOT TARGET_POSIX AND HAVE_TCP_FASTOPEN)
    set(WITH_TCP_FASTOPEN TRUE)
endif()

target_compile_options(neosocksd PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
# be strict with original sources
target_compile_options(neosocksd PRIVATE -pedantic -Wall -Wextra)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(neosocksd PRIVATE -Werror)
endif()

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if((NOT EXISTS ${LIBEV_INCLUDE_DIR}) OR (NOT EXISTS ${LIBEV_LIBRARY}))
    message(FATAL_ERROR "libev not found")
endif()
message(STATUS "libev: ${LIBEV_LIBRARY}")
target_include_directories(neosocksd SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LIBEV_LIBRARY})

# find c-ares
find_path(LIBCARES_INCLUDE_DIR NAMES ares.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBCARES_LIBRARY NAMES libcares.a)
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
    message(STATUS "c-ares: ${LIBCARES_VERSION}")
    message(STATUS "c-ares: ${LIBCARES_LIBRARY}")
    set(WITH_CARES TRUE)
    target_include_directories(neosocksd SYSTEM PRIVATE ${LIBCARES_INCLUDE_DIR})
    target_link_libraries(neosocksd PRIVATE ${LIBCARES_LIBRARY})
endif()

# find lua
find_path(LUA_INCLUDE_DIR
    NAMES luaconf.h lua.h lualib.h lauxlib.h
    PATH_SUFFIXES
    include/lua54 include/lua5.4 include/lua-5.4
    include/lua53 include/lua5.3 include/lua-5.3
    include/lua include
)
if(BUILD_STATIC OR LINK_STATIC_LUA)
    find_library(LUA_LIBRARY
        NAMES
        liblua54.a liblua5.4.a liblua-5.4.a
        liblua53.a liblua5.3.a liblua-5.3.a
        liblua.a
        PATH_SUFFIXES
        lib/lua54 lib/lua5.4 lib/lua-5.4
        lib/lua53 lib/lua5.3 lib/lua-5.3
        lib/lua lib
    )
else()
    find_library(LUA_LIBRARY
        NAMES
        lua54 lua5.4 lua-5.4
        lua53 lua5.3 lua-5.3
        lua
        PATH_SUFFIXES
        lib/lua54 lib/lua5.4 lib/lua-5.4
        lib/lua53 lib/lua5.3 lib/lua-5.3
        lib/lua lib
    )
endif()
if(EXISTS "${LUA_INCLUDE_DIR}/lua.h")
    file(READ "${LUA_INCLUDE_DIR}/lua.h" LUA_VERSION_STR)
    string(REGEX MATCH "#define LUA_VERSION_MAJOR[ \t]+\"([^\n]*)\"" _ ${LUA_VERSION_STR})
    set(LUA_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define LUA_VERSION_MINOR[ \t]+\"([^\n]*)\"" _ ${LUA_VERSION_STR})
    set(LUA_VERSION_MINOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define LUA_VERSION_RELEASE[ \t]+\"([^\n]*)\"" _ ${LUA_VERSION_STR})
    set(LUA_VERSION_RELEASE ${CMAKE_MATCH_1})
    set(LUA_VERSION "${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}.${LUA_VERSION_RELEASE}")
endif()
if((NOT ${LUA_VERSION} VERSION_GREATER_EQUAL "5.3.0") OR (NOT EXISTS ${LUA_LIBRARY}))
    message(WARNING "Lua (>= 5.3) not found, ruleset is unavailable")
else()
    message(STATUS "Lua: ${LUA_VERSION}")
    message(STATUS "Lua: ${LUA_LIBRARY}")
    set(WITH_LUA TRUE)
    target_include_directories(neosocksd SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
    target_link_libraries(neosocksd PRIVATE ${LUA_LIBRARY})
endif()

if(WITH_LUA)
    target_link_libraries(neosocksd PRIVATE ${CMAKE_DL_LIBS})
    set(WITH_RULESET TRUE)
endif()

# find systemd
if(NOT BUILD_STATIC)
    find_path(SYSTEMD_INCLUDE_DIR NAMES systemd/sd-daemon.h)
    find_library(SYSTEMD_LIBRARY NAMES systemd)
    if((EXISTS ${SYSTEMD_INCLUDE_DIR}) AND (EXISTS ${SYSTEMD_LIBRARY}))
        message(STATUS "systemd: ${SYSTEMD_LIBRARY}")
        set(WITH_SYSTEMD TRUE)
        target_include_directories(neosocksd SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIR})
        target_link_libraries(neosocksd PRIVATE ${SYSTEMD_LIBRARY})
    endif()
endif()

include(CheckLibraryExists)
check_library_exists(m ldexp "" LIBM)
if(LIBM)
    target_link_libraries(neosocksd PRIVATE m)
endif()

install(TARGETS neosocksd DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
