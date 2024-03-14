cmake_minimum_required(VERSION 3.16)
project(kpabe_proxy)

set(CMAKE_C_COMPILER cc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 20)
set(CXXFLAGS "-march=x86-64-v3 -O2 -Wall -Wextra -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CXXFLAGS}")

# Specify RELIC include directory
#include_directories(
#    /usr/local/include/relic
#    /usr/local/include/lsss
#)

find_package(nlohmann_json 3.2.0 REQUIRED)

file(
    GLOB_RECURSE
    kpabe_sources
    kpabe-content-filtering/dpvs/*
    kpabe-content-filtering/keys/*
    kpabe-content-filtering/kpabe/*
    kpabe-content-filtering/utils.c
    kpabe-content-filtering/utils.h
)

add_executable(
    proxy
    main.cpp
    logger.cpp
    kpabe_client.cpp
    socket_handler_manager.cpp
    http_proxy_server.cpp
    http_client.cpp
    http_response.cpp
    picohttpparser/picohttpparser.c
    kpabe_utils.cpp
    ssl_utils.cpp
    ${kpabe_sources}
)

target_link_libraries(proxy ssl crypto relic_s lsss gmp nlohmann_json::nlohmann_json)

add_executable(
    server
    main_server.cpp
    logger.cpp
    socket_handler_manager.cpp
    https_server.cpp
    picohttpparser/picohttpparser.c
    kpabe_utils.cpp
    ssl_utils.cpp
    ${kpabe_sources}
)

target_link_libraries(server ssl crypto relic_s lsss gmp)

add_executable(
    verifier
    main_verifier.cpp
    logger.cpp
    socket_handler_manager.cpp
    netfilter_handler.cpp
    kpabe_server.cpp
    kpabe_utils.cpp
    ssl_utils.cpp
    ${kpabe_sources}
)

target_link_libraries(verifier ssl crypto relic_s lsss gmp nlohmann_json::nlohmann_json mnl netfilter_queue)
