cmake_minimum_required(VERSION 3.6)
project(license-cxx VERSION 1.0.0 LANGUAGES CXX)

set(LCC_PROJECT_NAME "license-cxx" CACHE STRING "License-CXX") 
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -fPIC")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library(license_cxx SHARED
    src/auth_util.cc
    src/base64.cc
    src/machineid.cc
    src/rsa_util.cc)

add_executable(license_gen 
    src/license_gen.cc
    src/auth_util.cc
    src/base64.cc
    src/machineid.cc
    src/rsa_util.cc)

target_link_libraries(license_cxx OpenSSL::Crypto)
target_link_libraries(license_gen OpenSSL::Crypto)
target_include_directories(license_cxx PRIVATE src)
