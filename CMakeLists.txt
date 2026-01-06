cmake_minimum_required(VERSION 3.17)
project(VSTChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

# Линковка 
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
    set(COMMON_LIBS OpenSSL::SSL OpenSSL::Crypto ws2_32)
else()
    set(COMMON_LIBS OpenSSL::SSL OpenSSL::Crypto pthread stdc++fs)
endif()

add_executable(VSTChat_server server.cpp)
target_link_libraries(VSTChat_server ${COMMON_LIBS})

add_executable(VSTChat_client client.cpp)
target_link_libraries(VSTChat_client ${COMMON_LIBS})