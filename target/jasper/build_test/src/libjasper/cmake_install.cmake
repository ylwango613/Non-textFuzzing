# Install script for directory: /data/ylwang/non-textfuzz/target/jasper/src/libjasper

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/data/ylwang/non-textfuzz/target/jasper/build_test/install")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/data/ylwang/non-textfuzz/target/jasper/build_test/src/libjasper/libjasper.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/jasper" TYPE FILE FILES
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_cm.h"
    "/data/ylwang/non-textfuzz/target/jasper/build_test/src/libjasper/include/jasper/jas_config.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_debug.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_dll.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_fix.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_getopt.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_icc.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_image.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_init.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_malloc.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_math.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jasper.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_seq.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_stream.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_string.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_tmr.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_tvp.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_types.h"
    "/data/ylwang/non-textfuzz/target/jasper/src/libjasper/include/jasper/jas_version.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/data/ylwang/non-textfuzz/target/jasper/build_test/src/libjasper/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
