add_library(csnippets STATIC)
target_include_directories(csnippets BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(csnippets PRIVATE -pedantic -Wall -Wextra -Werror)
add_subdirectory(net)
add_subdirectory(utils)
