add_executable(neosocksd
    util.c util.h
    conf.c conf.h
    sockutil.c sockutil.h
    dialer.c dialer.h
    resolver.c resolver.h
    ruleset.c ruleset.h
    transfer.c transfer.h
    forward.c forward.h
    socks.c socks.h
    http_proxy.c http_api.c http_invoke.c http_impl.h http.c http.h
    server.c server.h
    main.c
)

target_include_directories(neosocksd BEFORE
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/contrib/csnippets"
)
target_link_libraries(neosocksd PRIVATE csnippets)

if(NOT TARGET_POSIX AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "GNU/Linux System: ${CMAKE_SYSTEM_VERSION}")
    set(TARGET_GNU_LINUX ON)
else()
    message(STATUS "POSIX-compliant System: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION}")
    set(TARGET_GNU_LINUX OFF)
endif()

if(TARGET_GNU_LINUX)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")
    target_compile_definitions(neosocksd PRIVATE _GNU_SOURCE)
else()
    list(APPEND CMAKE_REQUIRED_DEFINITIONS "-D_POSIX_C_SOURCE=200809L")
    target_compile_definitions(neosocksd PRIVATE _POSIX_C_SOURCE=200809L)
endif()

include(CheckSymbolExists)
check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
check_symbol_exists(gettimeofday "sys/time.h" HAVE_GETTIMEOFDAY)
check_symbol_exists(IP_TRANSPARENT "netinet/in.h" HAVE_IP_TRANSPARENT)
check_symbol_exists(SO_BINDTODEVICE "sys/socket.h" HAVE_SO_BINDTODEVICE)
check_symbol_exists(SO_REUSEPORT "sys/socket.h" HAVE_SO_REUSEPORT)
check_symbol_exists(TCP_FASTOPEN "netinet/tcp.h" HAVE_TCP_FASTOPEN)

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
target_include_directories(neosocksd SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LIBEV_LIBRARY})

# find c-ares
find_path(LIBCARES_INCLUDE_DIR NAMES ares.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBCARES_LIBRARY NAMES libcares.a)
else()
    find_library(LIBCARES_LIBRARY NAMES cares)
endif()
if((EXISTS ${LIBCARES_INCLUDE_DIR}) AND (EXISTS ${LIBCARES_LIBRARY}))
    message(STATUS "c-ares: ${LIBCARES_LIBRARY}")
    set(WITH_CARES ON)
else()
    message(FATAL_ERROR "c-ares not found")
endif()
target_include_directories(neosocksd SYSTEM PRIVATE ${LIBCARES_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LIBCARES_LIBRARY})

# find lua
find_path(LUA_INCLUDE_DIR
    NAMES luaconf.h lua.h lualib.h lauxlib.h
    PATH_SUFFIXES
    include/lua54 include/lua5.4 include/lua-5.4
    include/lua53 include/lua5.3 include/lua-5.3
    include/lua include
)
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
if((EXISTS ${LUA_INCLUDE_DIR}) AND (EXISTS ${LUA_LIBRARY}))
    message(STATUS "Lua: ${LUA_LIBRARY}")
else()
    message(FATAL_ERROR "Lua not found")
endif()
target_include_directories(neosocksd SYSTEM PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(neosocksd PRIVATE ${LUA_LIBRARY} ${CMAKE_DL_LIBS})

install(TARGETS neosocksd DESTINATION bin)

configure_file(config.h.in config.h ESCAPE_QUOTES)
