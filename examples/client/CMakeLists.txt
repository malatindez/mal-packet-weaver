
file(GLOB_RECURSE CLIENT_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.*"
)

if(MSVC) # update filters in MSVC
foreach(_source IN ITEMS ${CLIENT_SOURCES})
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

add_executable(client ${CLIENT_SOURCES})

target_link_libraries(client PUBLIC mal-packet-weaver)
target_include_directories(client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/../examples-common")