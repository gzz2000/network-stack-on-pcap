
add_executable(linktest linktest/linktest.cpp)
target_link_libraries(linktest PUBLIC link)

add_executable(iptest iptest/iptest.cpp)
target_link_libraries(iptest PUBLIC ip)

add_executable(tcptest_client_kernelstack tcptest/client.cpp)
add_executable(tcptest_server_kernelstack tcptest/server.cpp)

set(LIBS_LINK "-Wl,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept,--wrap=read,--wrap=write,--wrap=close,--wrap=getaddrinfo,--wrap=freeaddrinfo,--wrap=send,--wrap=sendto,--wrap=recv,--wrap=recvfrom,--wrap=setsockopt" tcp)

add_executable(tcptest_client_wrap tcptest/client.cpp)
add_executable(tcptest_server_wrap tcptest/server.cpp)
target_link_libraries(tcptest_client_wrap ${LIBS_LINK})
target_link_libraries(tcptest_server_wrap ${LIBS_LINK})

