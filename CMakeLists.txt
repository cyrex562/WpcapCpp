cmake_minimum_required(VERSION 3.8)
project(WpcapCpp)

set(CMAKE_CXX_STANDARD 11)

include_directories("D:\\Projects\\npcap-sdk\\Include")

set(SOURCE_FILES
        main.cpp)

add_executable(WpcapCpp ${SOURCE_FILES})
