cmake_minimum_required(VERSION 3.17)
project(package_sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS -pthread)

include(FindPCAP.cmake)
include_directories("/usr/include/")

add_executable(
        package_sniffer main.cpp
        sniffer/sources/packet_sniffer.cpp
        sniffer/headers/packet_sniffer.h
        ${SOURCE_FILES}
        package/headers/ethernet/ethernet_header.cpp
        package/headers/ethernet/ethernet_header.h
        package/headers/ip/ip_header.cpp
        package/headers/ip/ip_header.h
        package/tcp/tcp_package.cpp
        package/tcp/tcp_package.h
        package/generic_package.h
        server/sources/ws_broadcast_server.cpp
        server/headers/ws_broadcast_server.h package/generic_package.cpp utils/nlohmann_json_conversion/convert_to_json.h utils/nlohmann_json_conversion/convert_to_json.cpp)

target_link_libraries(package_sniffer ${PCAP_LIBRARY})
target_link_libraries(package_sniffer "/usr/lib/x86_64-linux-gnu/libiw.so")
target_link_libraries(package_sniffer "/usr/lib/x86_64-linux-gnu/libiw.a")