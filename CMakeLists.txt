cmake_minimum_required(VERSION 3.15)
project(tp C CXX)
set(CMAKE_CXX_STANDARD 17)

add_compile_options(-Wall -Wextra)

set(GWHF_FW_SOURCES
    framework/gwhf/ev/epoll.c
    framework/gwhf/http/request.c
    framework/gwhf/http/response.c
    framework/gwhf/gwhf.c
    framework/gwhf/helpers.c
    framework/gwhf/buf.c
    framework/gwhf/client.c
    framework/gwhf/route.c
    framework/gwhf/stack16.c
    framework/gwhf/stream.c
    framework/gwhf/thread.c
    framework/gwhf/ssl.c)

set(GWHF_FW_DEFINES
    GWHF_ARCH_AMD64
    CONFIG_HTTPS)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(GWHF_FW_SOURCES ${GWHF_FW_SOURCES}
        framework/gwhf/os/linux/signal.c
        framework/gwhf/os/linux/socket.c)
    set(GWHF_FW_DEFINES ${GWHF_FW_DEFINES} GWHF_OS_LINUX)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(GWHF_FW_SOURCES ${GWHF_FW_SOURCES}
        framework/gwhf/ext/wepoll/wepoll.c
        framework/gwhf/ext/tinycthread/tinycthread.c
        framework/gwhf/os/windows/socket.c)
    set(GWHF_FW_DEFINES ${GWHF_FW_DEFINES} GWHF_OS_WINDOWS)
endif()

add_library(gwhf SHARED ${GWHF_FW_SOURCES})
include_directories(framework/gwhf/include)
target_compile_definitions(gwhf PRIVATE ${GWHF_FW_DEFINES})

find_package(OpenSSL REQUIRED)
target_link_libraries(gwhf PRIVATE
                        OpenSSL::SSL
                        OpenSSL::Crypto)

add_executable(main app/main.c)
target_link_libraries(main PRIVATE gwhf)
