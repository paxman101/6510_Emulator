cmake_minimum_required(VERSION 3.21)
project(6510 C)

set(CMAKE_C_STANDARD 17)

#include_directories(./)

#SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

#set(THREADS_PREFER_PTHREAD_FLAG ON)
#find_package(Threads REQUIRED)

add_library(6510 STATIC cpu.c memory.c)
target_include_directories(6510 PUBLIC ${PROJECT_SOURCE_DIR})
add_executable(test6510 main.c cpu.c memory.c)

#target_link_libraries(6510)
