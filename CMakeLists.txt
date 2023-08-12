cmake_minimum_required(VERSION 3.15)
project(mal-packet-weaver VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost REQUIRED COMPONENTS system serialization context coroutine HINTS "
  C:/" 
  "C:/Boost" 
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")


add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/third_party/mal-toolkit" EXCLUDE_FROM_ALL)

file(GLOB_RECURSE MAL_PACKET_WEAVER_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/mal-packet-weaver/*.*"
)

add_library(mal-packet-weaver ${MAL_PACKET_WEAVER_SOURCES})

target_link_libraries(mal-packet-weaver PUBLIC mal-toolkit)

target_include_directories(mal-packet-weaver PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(mal-packet-weaver PUBLIC ${Boost_LIBRARIES})

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL)

if(OPENSSL_FOUND)
    target_include_directories(mal-packet-weaver PUBLIC ${OPENSSL_INCLUDE_DIR})
    
    target_link_libraries(mal-packet-weaver PUBLIC ${OPENSSL_LIBRARIES})
else()
    message(WARNING "OpenSSL not found")
endif()
