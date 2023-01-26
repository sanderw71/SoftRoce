# Author : Sander Weijers

project (udp_receiver)

cmake_minimum_required(VERSION 3.4)

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_BUILD_TYPE Debug) # or debug if you need to use gdb on it.

# Some how g++ has better performance than clang++. Of course I don't know all flags for clang++.
set(CMAKE_CXX_COMPILER g++) # or clang++
#set(CMAKE_CXX_COMPILER clang++) # or clang++
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Ofast -ffast-math -funroll-loops -march=native") # get crazy here
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -march=native") # get crazy here
add_compile_options("-g")
set(CMAKE_CXX_FLAGS "-O1  -ggdb")

#find_library(IBVERBS_LIBRARY ibverbs HINTS /home/atr/local/lib)
#find_library(RDMACM_LIBRARY rdmacm HINTS /home/atr/local/lib)

link_libraries(pthread ${IBVERBS_LIBRARY} ${RDMACM_LIBRARY})

include_directories("${PROJECT_SOURCE_DIR}" "/home/atr/local/include/")

add_executable(udp_client ${PROJECT_SOURCE_DIR}/udp_client.c)
add_executable(udp_server ${PROJECT_SOURCE_DIR}/net_utils.c ${PROJECT_SOURCE_DIR}/udp_server.c ${PROJECT_SOURCE_DIR}/crc32.c ${PROJECT_SOURCE_DIR}/udp_server.c)
add_executable(crc_check ${PROJECT_SOURCE_DIR}/crc32.c ${PROJECT_SOURCE_DIR}/crc_check.c)

