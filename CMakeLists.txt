cmake_minimum_required(VERSION 3.7)
project(OS_HW4)

set(CMAKE_C_STANDARD 90)

set(SOURCE_FILES
        pcc_client.c
        pcc_server.c)
add_executable(OS_HW4 ${SOURCE_FILES})