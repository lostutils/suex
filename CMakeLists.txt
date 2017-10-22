cmake_minimum_required(VERSION 3.7)

include(ExternalProject)
project(suex)

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

IF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
SET(CMAKE_INSTALL_PREFIX /usr/local CACHE PATH "Install in /usr/local directory." FORCE)
ENDIF(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(CMAKE_CXX_FLAGS "-O0 -Wall -Werror")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

file(GLOB_RECURSE SOURCE_FILES "include/*.h" "src/*.*pp" "deps/backward-cpp/backward.*pp")
include_directories(include deps)
add_executable(suex ${SOURCE_FILES})

# suex depends on libpam and libdw
target_link_libraries(suex pam dw)

# generating man pages from markdown using ronn
add_custom_command(TARGET suex POST_BUILD
        DEPENDS suex
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/man
        COMMENT "Generating man pages..."
        COMMAND ronn -r suex.md
        COMMAND ronn -r suex.conf.md
        COMMAND mv -f suex.5 suex.conf.5)

add_custom_target(secure
        COMMAND chown root:root ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/suex
        COMMAND chmod a+x ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/suex
        COMMAND chmod u+s ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/suex)

install(FILES ${CMAKE_SOURCE_DIR}/man/suex.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1)
install(FILES ${CMAKE_SOURCE_DIR}/man/suex.conf.5 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man5)
install(FILES ${CMAKE_SOURCE_DIR}/doc/suex.conf DESTINATION /etc/
   PERMISSIONS OWNER_READ GROUP_READ)

install(TARGETS suex
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_EXECUTE SETUID
        RUNTIME DESTINATION bin)

set(CPACK_GENERATOR "RPM;DEB")
set(CPACK_SYSTEM_NAME "linux-${CPU_ARCH}")
set(CPACK_PACKAGE_NAME "suex")
set(CPACK_PACKAGE_VENDOR "odedlaz")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Oded Lazar")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "execute commands as another user")
set(CPACK_RPM_PACKAGE_RELOCATABLE TRUE)
set(CPACK_RPM_RELOCATION_PATHS /etc)
set(CPACK_PACKAGE_VERSION "0.2.2")
set(CPACK_DEBIAN_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${CPU_ARCH}")
set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/pkg")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
include(CPack)
