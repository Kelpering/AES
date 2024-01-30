cmake_minimum_required(VERSION 3.25.1)
project(AES)

include_directories(include)

file (GLOB SOURCES "src/*.c")

add_executable(AES ${SOURCES})

target_compile_options(AES PRIVATE
    -Wall -Wextra -Wpedantic
)