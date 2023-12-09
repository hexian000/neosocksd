add_library(miniz STATIC miniz.c miniz.h)
target_include_directories(miniz BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(miniz PRIVATE -w)
target_compile_definitions(miniz
    PUBLIC
    MINIZ_NO_STDIO
    MINIZ_NO_ARCHIVE_APIS
    MINIZ_NO_ARCHIVE_WRITING_APIS
    MINIZ_NO_ZLIB_APIS
    MINIZ_NO_ZLIB_COMPATIBLE_NAME
    MINIZ_NO_MALLOC
)
