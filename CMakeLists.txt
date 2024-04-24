cmake_minimum_required(VERSION 3.15)
project(mal-packet-weaver VERSION 0.0.1)
cmake_policy(SET CMP0060 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost REQUIRED COMPONENTS system context coroutine HINTS "
  C:/" 
  "C:/Boost" 
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/third_party/mal-toolkit" EXCLUDE_FROM_ALL)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/third_party/cereal" EXCLUDE_FROM_ALL)

set(CEREAL_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cereal/include")

file(GLOB_RECURSE MAL_PACKET_WEAVER_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/mal-packet-weaver/*.*"
)
if(MSVC) # update filters in MSVC
foreach(_source IN ITEMS ${MAL_PACKET_WEAVER_SOURCES})
  if(IS_ABSOLUTE "${_source}")
    file(RELATIVE_PATH _source_rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_source}")
  else()
    set(_source_rel "${_source}")
  endif()

  get_filename_component(_source_path "${_source_rel}" PATH)
  string(REPLACE "/" "\\" _source_path_msvc "${_source_path}")
  source_group("${_source_path_msvc}" FILES "${_source}")
endforeach()
endif()

add_library(mal-packet-weaver STATIC ${MAL_PACKET_WEAVER_SOURCES})

target_link_libraries(mal-packet-weaver PUBLIC mal-toolkit)

target_include_directories(mal-packet-weaver PUBLIC ${Boost_INCLUDE_DIRS})
target_include_directories(mal-packet-weaver PUBLIC ${CEREAL_INCLUDE_DIRS})
target_include_directories(mal-packet-weaver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mal-packet-weaver)
target_link_libraries(mal-packet-weaver PUBLIC ${Boost_LIBRARIES})

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL)

if(OPENSSL_FOUND)
    target_include_directories(mal-packet-weaver PUBLIC ${OPENSSL_INCLUDE_DIR})
    
    target_link_libraries(mal-packet-weaver PUBLIC OpenSSL::Crypto)
else()
    message(WARNING "OpenSSL not found")
endif()


option(BUILD_EXAMPLES "Build examples" OFF)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()