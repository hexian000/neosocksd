target_sources(csnippets
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/dispatcher.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/dispatcher.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/task.h"
)
