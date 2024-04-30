cmake_minimum_required(VERSION 3.5)

set(CMAKE_USER_MAKE_RULES_OVERRIDE "${CMAKE_SOURCE_DIR}/cmake/modules/OverrideInitFlags.cmake")

project(bchp2p LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# If ccache is available, then use it.
find_program(CCACHE ccache)
if(CCACHE)
  message(STATUS "Using ccache: ${CCACHE}")
  set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
endif(CCACHE)

# Fmt lib
find_package(fmt REQUIRED)

# asio
find_package(asio REQUIRED)

# Boost
find_package(Boost 1.71.0 REQUIRED)

# Simple Web Server
set(USE_STANDALONE_ASIO ON CACHE INTERNAL "Used by Simple-Web-Server, disabled" FORCE)
set(BUILD_TESTING OFF CACHE INTERNAL "Used by Simple-Web-Server, disabled" FORCE)
set(BUILD_FUZZING OFF CACHE INTERNAL "Used by Simple-Web-Server, disabled" FORCE)
set(USE_OPENSSL OFF CACHE INTERNAL "Used by Simple-Web-Server, disabled" FORCE)
add_subdirectory(Simple-Web-Server)

# UniValue
set(BUILD_BENCH OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
set(BUILD_TESTS OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
add_subdirectory(univalue)
target_compile_options(univalue PRIVATE -Wall -Wno-unused-parameter)

# BCHN modified sources, as a lib
add_subdirectory(src/bitcoin)
# /BCHN


# Testing echoserver using asio
add_executable(asiotest src/asiotest.cpp src/util.cpp)
target_compile_options(asiotest PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(asiotest fmt::fmt asio::asio univalue bitcoin)

# bchp2p using asio
add_executable(bchp2p src/bchp2p.cpp src/util.cpp src/html_bits.cpp)
target_compile_options(bchp2p PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(bchp2p fmt::fmt asio::asio Boost::boost univalue bitcoin simple-web-server)

add_compile_definitions(VERSION_STR=\"${CMAKE_PROJECT_VERSION}\")

#include(GNUInstallDirs)
#install(TARGETS bchp2p
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#)
