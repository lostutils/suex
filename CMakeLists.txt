cmake_minimum_required(VERSION 3.7)
include(ExternalProject)
project(runas)

set(CMAKE_CXX_STANDARD 14)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_INSTALL_PREFIX /usr/local)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "-O0")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

#------------ google re2 ------------------

set(RE2_ROOT_DIR ${CMAKE_SOURCE_DIR}/deps/re2)
set(RE2_BINARY_DIR ${CMAKE_BINARY_DIR}/re2)
ExternalProject_Add(project_re2
   URL ${RE2_ROOT_DIR}/src
  CONFIGURE_COMMAND ""

  PREFIX        ${RE2_BINARY_DIR}
  TMP_DIR       ${RE2_BINARY_DIR}/tmp
  STAMP_DIR     ${RE2_BINARY_DIR}/stamp
  BINARY_DIR    ${RE2_BINARY_DIR}/src
  SOURCE_DIR    ${RE2_BINARY_DIR}/src
  INSTALL_DIR   ${RE2_BINARY_DIR}

  BUILD_COMMAND $(MAKE)
  INSTALL_COMMAND $(MAKE) DESTDIR=${RE2_ROOT_DIR} install
)

add_library(re2 STATIC IMPORTED)
set_property(TARGET re2 PROPERTY IMPORTED_LOCATION ${RE2_ROOT_DIR}/lib/libre2.a)
add_dependencies(re2 project_re2)

#------------ end of google re2 ------------------

file(GLOB_RECURSE SOURCE_FILES "include/*.h" "src/*.cpp")
include_directories(include ${RE2_ROOT_DIR}/include)
add_executable(runas ${SOURCE_FILES})

install(TARGETS runas
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_EXECUTE SETUID
        RUNTIME DESTINATION bin)

target_link_libraries(runas re2)
