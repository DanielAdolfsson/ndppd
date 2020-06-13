cmake_minimum_required(VERSION 3.10)
project(ndppd C)
set(CMAKE_C_STANDARD 99)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC)

add_executable(ndppd ${SRC})
target_compile_options(ndppd PRIVATE -O2 -Werror -Wall -Wextra
        -fno-strict-aliasing
        -Wno-strict-aliasing
        -Wno-missing-braces
        -Wno-missing-field-initializers
        -Wno-address-of-packed-member
)

