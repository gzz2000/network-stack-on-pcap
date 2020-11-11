cmake_minimum_required(VERSION 3.10)

project(lab2)

# find_package(PCAP REQUIRED)
include(thirdparty/FindPCAP.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -lpthread -O0 -Wall -Wextra -Wconversion -ggdb3 -DZDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -lpthread -O2 -Wall -Wextra -Wconversion")

include_directories(PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(link link/device.cpp link/ethernet.cpp link/getaddr.cpp link/compose.cpp)
target_link_libraries(link PUBLIC ${PCAP_LIBRARY})

add_library(ip ip/routing.cpp ip/ip.cpp)
target_link_libraries(ip PUBLIC ${PCAP_LIBRARY} link)

add_subdirectory(app)
