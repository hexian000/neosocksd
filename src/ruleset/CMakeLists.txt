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
    add_unit_test(cfunc_test
        SRCS cfunc_test.c ../ruleset.c base.c cfunc.c
        CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
        EXTRA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/.."
        WITH_LUA)
    add_unit_test(api_test
        SRCS api_test.c api.c base.c
        CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
        EXTRA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/.."
        WITH_LUA)
    add_unit_test(await_test
        SRCS await_test.c await.c base.c
        CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
        EXTRA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/.."
        WITH_LUA)
endif()
