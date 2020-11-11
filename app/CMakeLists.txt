
add_executable(linktest linktest/linktest.cpp)
target_link_libraries(linktest PUBLIC link)

add_executable(iptest iptest/iptest.cpp)
target_link_libraries(iptest PUBLIC ip)
