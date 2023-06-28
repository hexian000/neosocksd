add_executable(neosocksd
    util.c util.h
    conf.c conf.h
    sockutil.c sockutil.h
    resolver.c resolver.h
    dialer.c dialer.h
    ruleset.c ruleset.h
    transfer.c transfer.h
    forward.c forward.h
    socks.c socks.h
    http.c http.h
    server.c server.h
    stats.c stats.h
    main.c
)

target_include_directories(neosocksd BEFORE
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/contrib/csnippets"
)
target_link_libraries(neosocksd PRIVATE csnippets)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT POSIX)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    target_compile_definitions(neosocksd PRIVATE _GNU_SOURCE)
else()
    message(STATUS "POSIX System: ${CMAKE_SYSTEM_NAME}")
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
    target_compile_definitions(neosocksd PRIVATE _POSIX_C_SOURCE=200809L)
endif()

include(CheckSymbolExists)
check_symbol_exists(IP_TRANSPARENT "netinet/in.h" HAVE_IP_TRANSPARENT)
check_symbol_exists(SO_BINDTODEVICE "sys/socket.h" HAVE_SO_BINDTODEVICE)
check_symbol_exists(SO_REUSEPORT "sys/socket.h" HAVE_SO_REUSEPORT)

target_compile_options(neosocksd PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/config.h")

# be strict with original sources
target_compile_options(neosocksd PRIVATE -pedantic -Wall -Wextra -Werror)

find_library(LIBM NAMES m)
if(LIBM)
    target_link_libraries(neosocksd PRIVATE ${LIBM})
endif()

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if((EXISTS ${LIBEV_INCLUDE_DIR}) AND (EXISTS ${LIBEV_LIBRARY}))
    message(STATUS "libev: ${LIBEV_LIBRARY}")
else()
    message(FATAL_ERROR "libev not found")
endif()
target_include_directories(neosocksd PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LIBEV_LIBRARY})

# find lua
find_path(LUA_INCLUDE_DIR
    NAMES lua.h
    PATH_SUFFIXES
    include/lua54 include/lua5.4 include/lua-5.4 include/lua include
)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LUA_LIBRARY
        NAMES liblua54.a liblua5.4.a liblua-5.4.a liblua.a
        PATH_SUFFIXES
        lib/lua54 lib/lua5.4 lib/lua-5.4 lib/lua lib
    )
else()
    find_library(LUA_LIBRARY
        NAMES lua54 lua5.4 lua-5.4 lua
        PATH_SUFFIXES
        lib/lua54 lib/lua5.4 lib/lua-5.4 lib/lua lib
    )
endif()
if((EXISTS ${LUA_INCLUDE_DIR}) AND (EXISTS ${LUA_LIBRARY}))
    message(STATUS "lua: ${LUA_LIBRARY}")
else()
    message(FATAL_ERROR "lua not found")
endif()
target_include_directories(neosocksd PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LUA_LIBRARY})

install(TARGETS neosocksd DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
