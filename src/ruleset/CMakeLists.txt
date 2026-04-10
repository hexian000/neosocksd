target_sources(neosocksd
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/await.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/base.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/cfunc.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/marshal.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/regex.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/time.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/zlib.h"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/api.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/await.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/base.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/cfunc.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/marshal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/regex.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/time.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/zlib.c"
)

if(WITH_LUA)
    add_executable(cfunc_test
        cfunc_test.c
    )
    target_include_directories(cfunc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_compile_options(cfunc_test PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
    target_compile_options(cfunc_test PRIVATE -pedantic -Wall -Wextra -Werror)
    target_link_libraries(cfunc_test PRIVATE csnippets miniz ${LIBEV_LIBRARY} ${LUA_LIBRARY})
    if(LIBM)
        target_link_libraries(cfunc_test PRIVATE m)
    endif()

    if(FORCE_POSIX)
        target_compile_definitions(cfunc_test PRIVATE _POSIX_C_SOURCE=200809L)
    else()
        target_compile_definitions(cfunc_test PRIVATE _GNU_SOURCE)
    endif()

    add_test(NAME cfunc_test COMMAND cfunc_test)
endif()
