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

add_unit_test(api_test
    SRCS api_test.c api.c base.c ../conf.c ../proto/codec.c "${CMAKE_CURRENT_BINARY_DIR}/../version.c"
    CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
    WITH_LUA)
add_unit_test(await_test
    SRCS await_test.c base.c ../proto/codec.c
    MOCK_SRCS await.c
    MOCK_DEFINITIONS fork=test_await_fork kill=test_await_kill
    CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
    WITH_LUA)
add_unit_test(ruleset_test
    SRCS ruleset_test.c base.c ../conf.c ../proto/codec.c "${CMAKE_CURRENT_BINARY_DIR}/../version.c"
    MOCK_SRCS ruleset.c cfunc.c
    MOCK_DEFINITIONS
        realloc=test_ruleset_realloc
        free=test_ruleset_free
        lua_newstate=test_ruleset_newstate
    CONFIG_H "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
    WITH_LUA)

# Keep RPC result-copy faults separate from the VM allocator's malloc seam.
set_property(SOURCE ruleset.c APPEND PROPERTY COMPILE_DEFINITIONS
    "$<$<STREQUAL:$<TARGET_PROPERTY:NAME>,ruleset_test_mock_impl>:malloc=test_ruleset_malloc>")
set_property(SOURCE cfunc.c APPEND PROPERTY COMPILE_DEFINITIONS
    "$<$<STREQUAL:$<TARGET_PROPERTY:NAME>,ruleset_test_mock_impl>:malloc=test_rpcall_malloc>")

file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/tmp")
target_compile_definitions(ruleset_test PRIVATE
    TEST_TMPDIR="${PROJECT_BINARY_DIR}/tmp")
