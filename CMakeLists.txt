#
# CMakeLists.txt
#
# Copyright (C) 2010 - 2022 Alfred E. Heggestad
#

##############################################################################
#
# Versioning
#

cmake_minimum_required(VERSION 3.7)

project(srtperf)

set(CMAKE_BUILD_TYPE RelWithDebInfo)


##############################################################################
#
# Module/Package Includes
#


##############################################################################
#
# Compile options
#

set(CMAKE_C_STANDARD 11)

if(NOT MSVC)
  add_compile_options(-Wall -Wextra)
endif()


include_directories(
  src
  /usr/local/include
  /usr/local/include/re
  /opt/local/include
)

link_directories(
  /usr/local/lib
  /opt/local/lib
)

add_definitions(
  -DUSE_OPENSSL
  )

##############################################################################
#
# Source section
#

add_executable(${PROJECT_NAME} src/main.c src/hexdump.c)
target_link_libraries(${PROJECT_NAME} -lre -lsrtp2 -lcrypto -lz -lpthread)
