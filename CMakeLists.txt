cmake_minimum_required(VERSION 3.15)
project(tp C CXX)
set(CMAKE_CXX_STANDARD 17)

add_executable(main
        app/main.c
        framework/gwhf/ev/epoll.c
        framework/gwhf/http/request.c
        framework/gwhf/http/response.c
        framework/gwhf/gwhf.c
        framework/gwhf/helpers.c
        framework/gwhf/os/windows/socket.c
        framework/gwhf/buf.c
        framework/gwhf/client.c
        framework/gwhf/route.c
        framework/gwhf/stack16.c
        framework/gwhf/stream.c
        framework/gwhf/thread.c
        framework/gwhf/ext/tinycthread/tinycthread.c
        framework/gwhf/ext/wepoll/wepoll.c
        framework/gwhf/ssl.c)

target_include_directories(main PRIVATE framework/gwhf/include)
target_compile_definitions(main PRIVATE CONFIG_HTTPS GWHF_ARCH_AMD64 GWHF_OS_WIN32)
find_package(OpenSSL REQUIRED)
target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)
