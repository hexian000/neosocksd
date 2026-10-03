target_sources(neosocksd
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/await.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/base.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/cfunc.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/marshal.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/regex.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ruleset.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/time.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/zlib.h"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/api.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/await.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/base.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/cfunc.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/marshal.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/regex.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/ruleset.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/time.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/zlib.c"
)

if(WITH_LUA)
    add_unit_test(api_test
        SRCS api_test.c api.c base.c ../proto/codec.c
        CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
        EXTRA_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/.."
        WITH_LUA)
add_unit_test(await_test
    SRCS await_test.c base.c ../proto/codec.c
    MOCK_SRCS await.c
    MOCK_DEFINITIONS fork=test_await_fork
    CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
    WITH_LUA)
add_unit_test(ruleset_test
    SRCS ruleset_test.c base.c cfunc.c ../conf.c ../proto/codec.c "${CMAKE_CURRENT_BINARY_DIR}/../version.c"
    MOCK_SRCS ruleset.c
    MOCK_DEFINITIONS
        malloc=test_ruleset_malloc
        realloc=test_ruleset_realloc
        free=test_ruleset_free
        lua_newstate=test_ruleset_newstate
    CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
    WITH_LUA)
endif()
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/tmp")
target_compile_definitions(ruleset_test PRIVATE
    TEST_TMPDIR="${PROJECT_BINARY_DIR}/tmp")
