target_sources(csnippets
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/io.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stream.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/memory.h"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/stream.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/memory.c"
)
