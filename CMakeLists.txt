# SPDX-License-Identifier: GPL-2.0-only

cmake_minimum_required(VERSION 3.15)
project(tp C CXX)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(GWHF_SOURCES
	src/gwhf/tls/tls.c
	src/gwhf/tls/tls.h)

set(GWHF_DEFINES GWHF_ARCH_AMD64 CONFIG_HTTPS)

add_library(gwhf SHARED ${GWHF_SOURCES})
include_directories(src/)
target_compile_definitions(gwhf PRIVATE ${GWHF_DEFINES})

find_package(OpenSSL REQUIRED)
target_link_libraries(gwhf PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(main src/main.c)
target_link_libraries(main PRIVATE gwhf)
target_compile_definitions(main PRIVATE ${GWHF_DEFINES})
