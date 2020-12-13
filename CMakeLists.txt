cmake_minimum_required(VERSION 3.17)
project(package_sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS -pthread)

include(FindPCAP.cmake)
include_directories("/usr/include/")

add_executable(package_sniffer main.cpp
               ${SOURCE_FILES})

target_link_libraries(package_sniffer ${PCAP_LIBRARY})
target_link_libraries(package_sniffer "/usr/lib/x86_64-linux-gnu/libiw.so")
target_link_libraries(package_sniffer "/usr/lib/x86_64-linux-gnu/libiw.a")