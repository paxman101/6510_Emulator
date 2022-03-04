cmake_minimum_required(VERSION 3.21)
project(6510 C)

set(CMAKE_C_STANDARD 23)

add_executable(6510 main.c cpu.h)
add_executable(test6510 cpu.c)
