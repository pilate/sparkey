cmake_minimum_required(VERSION 3.16)

project(sparkey VERSION 2.0.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

option(SPARKEY_BUILD_SHARED "Build the shared library" ON)
option(SPARKEY_BUILD_STATIC "Build the static library" ON)
option(SPARKEY_WERROR "Treat compiler warnings as errors" OFF)

if(NOT SPARKEY_BUILD_SHARED AND NOT SPARKEY_BUILD_STATIC)
  message(FATAL_ERROR "At least one of SPARKEY_BUILD_SHARED and SPARKEY_BUILD_STATIC must be ON")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SNAPPY REQUIRED IMPORTED_TARGET snappy)
pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)

function(sparkey_set_warnings target)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wfloat-equal -Wshadow -Wpointer-arith -pedantic
      $<$<BOOL:${SPARKEY_WERROR}>:-Werror>)
  endif()
endfunction()

set(SPARKEY_SOURCES
  src/MurmurHash3.c
  src/buf.c
  src/compress.c
  src/endiantools.c
  src/hashalgorithms.c
  src/hashheader.c
  src/hashiter.c
  src/hashreader.c
  src/hashwriter.c
  src/logheader.c
  src/logreader.c
  src/logwriter.c
  src/returncodes.c
  src/util.c
)

set(SPARKEY_LIBRARIES)
if(SPARKEY_BUILD_SHARED)
  add_library(sparkey SHARED ${SPARKEY_SOURCES})
  # The ABI is unchanged since the libtool build, so keep its soname
  # (libsparkey.so.0) and existing binaries keep working.
  set_target_properties(sparkey PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)
  list(APPEND SPARKEY_LIBRARIES sparkey)
endif()
if(SPARKEY_BUILD_STATIC)
  add_library(sparkey_static STATIC ${SPARKEY_SOURCES})
  set_target_properties(sparkey_static PROPERTIES OUTPUT_NAME sparkey)
  list(APPEND SPARKEY_LIBRARIES sparkey_static)
endif()

foreach(lib IN LISTS SPARKEY_LIBRARIES)
  target_include_directories(${lib} PUBLIC ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(${lib} PRIVATE PkgConfig::SNAPPY PkgConfig::ZSTD)
  sparkey_set_warnings(${lib})
endforeach()

# Programs link against the shared library when it is built, as they did under libtool.
list(GET SPARKEY_LIBRARIES 0 SPARKEY_LINK_LIBRARY)

add_executable(sparkey_cli src/main.c)
set_target_properties(sparkey_cli PROPERTIES OUTPUT_NAME sparkey)
target_link_libraries(sparkey_cli PRIVATE ${SPARKEY_LINK_LIBRARY})
sparkey_set_warnings(sparkey_cli)

add_executable(bench src/bench.c)
target_link_libraries(bench PRIVATE ${SPARKEY_LINK_LIBRARY})
sparkey_set_warnings(bench)

if(BUILD_TESTING)
  foreach(test testvlq testhash testutil testsystem)
    add_executable(${test} src/${test}.c)
    target_link_libraries(${test} PRIVATE ${SPARKEY_LINK_LIBRARY})
    sparkey_set_warnings(${test})
    add_test(NAME ${test} COMMAND ${test})
  endforeach()
endif()

find_package(Doxygen)
if(DOXYGEN_FOUND)
  configure_file(Doxyfile.in Doxyfile @ONLY)
  add_custom_target(doc
    COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM)
endif()

install(TARGETS ${SPARKEY_LIBRARIES} sparkey_cli
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES src/sparkey.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sparkey)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
