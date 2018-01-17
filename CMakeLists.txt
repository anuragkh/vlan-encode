cmake_minimum_required(VERSION 2.8)
project(pathdump-decode C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g")
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-modules)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
file(MAKE_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})

find_package(PCAP REQUIRED)

include_directories(${PCAP_INCLUDE_DIR})
add_executable(encode src/encode_pcap.cc)
target_link_libraries(encode ${PCAP_LIBRARY})
