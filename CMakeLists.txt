cmake_minimum_required(VERSION 3.10)

project(lab2)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# find_package(PCAP REQUIRED)
include(thirdparty/FindPCAP.cmake)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -lpthread -O0 -Wall -Wno-sign-compare -ggdb3 -DZDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -lpthread -O2 -Wall -Wno-sign-compare")

include_directories(PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(link
  link/ethernet/device.cpp
  link/ethernet/ethernet.cpp
  link/ethernet/getaddr.cpp
  link/ethernet/compose.cpp)
target_link_libraries(link PUBLIC ${PCAP_LIBRARY} Threads::Threads)

add_library(ip
  ip/routing.cpp
  ip/ip.cpp)
target_link_libraries(ip PUBLIC ${PCAP_LIBRARY} Threads::Threads link)

add_library(tcp
  transport/tcp/net_interface.cpp
  transport/tcp/recv_segment.cpp
  transport/tcp/socket_wrapper.cpp
  transport/tcp/worker_conn.cpp
  transport/tcp/service.cpp)
target_link_libraries(tcp PUBLIC ${PCAP_LIBRARY} Threads::Threads link ip)

add_library(tcp_runtime SHARED
  transport/tcp/net_interface.cpp
  transport/tcp/recv_segment.cpp
  transport/tcp/socket_wrapper.cpp
  transport/tcp/worker_conn.cpp
  transport/tcp/service.cpp)
target_link_libraries(tcp_runtime PUBLIC ${PCAP_LIBRARY} Threads::Threads link ip)
target_compile_definitions(tcp_runtime PUBLIC RUNTIME_INTERPOSITION)

add_subdirectory(app)
