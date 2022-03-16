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


##############################################################################
#
# Module/Package Includes
#

find_package(OpenSSL)


##############################################################################
#
# Compile options
#

#option(USE_OPENSSL "Enable OpenSSL" ${OPENSSL_FOUND})

include_directories(
  src
  /usr/local/include
  /usr/local/include/re
  /usr/local/include/rem
  /opt/local/include
)

link_directories(
  /usr/local/lib
  /opt/local/lib
)

add_definitions(
  -DHAVE_INET6
  -DHAVE_LIBSRTP
  -DLIBSRTP_VERSION=2
  )

##############################################################################
#
# Source section
#

add_executable(${PROJECT_NAME}
  src/main.c
)
target_link_libraries(${PROJECT_NAME} -lrem -lre -lsrtp2 -lcrypto -lz -lpthread)
