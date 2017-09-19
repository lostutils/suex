cmake_minimum_required(VERSION 3.7)

include(ExternalProject)
project(doas)

# only linux supported at the moment
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "CPU architecture '${CMAKE_SYSTEM_NAME}' not supported")
endif ()

# void ptr = 8 byte --> x86_64 || void ptr != 8 byte --> x86
if (CMAKE_SIZEOF_VOID_P MATCHES 8)
    set(CPU_ARCH "amd64")
else ()
    set(CPU_ARCH "i386")
endif ()

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
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

file(GLOB_RECURSE SOURCE_FILES "include/*.h" "src/*.*pp" "deps/backward-cpp/backward.*pp")
include_directories(include deps)
add_executable(doas ${SOURCE_FILES})

# doas depends on libpam and libdw
target_link_libraries(doas pam dw)

# generating man pages from markdown using ronn
add_custom_command(TARGET doas POST_BUILD
        DEPENDS doas
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/man
        COMMENT "Generating man pages..."
        COMMAND ronn -r doas.md
        COMMAND ronn -r doas.conf.md
        COMMAND mv -f doas.5 doas.conf.5)

add_custom_target(secure
        COMMAND chown root:root ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/doas
        COMMAND chmod a+x ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/doas
        COMMAND chmod u+s ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/doas)

install(FILES ${CMAKE_SOURCE_DIR}/man/doas.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
install(FILES ${CMAKE_SOURCE_DIR}/man/doas.conf.5 DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man5)
install(TARGETS doas
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_EXECUTE SETUID
        RUNTIME DESTINATION bin)

set(CPACK_GENERATOR "RPM;DEB")
set(CPACK_SYSTEM_NAME "linux-${CPU_ARCH}")
set(CPACK_PACKAGE_NAME "doas")
set(CPACK_PACKAGE_VENDOR "odedlaz")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Oded Lazar")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "execute commands as another user")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/pkg")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
include(CPack)
