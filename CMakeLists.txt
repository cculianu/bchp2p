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

# UniValue
set(BUILD_BENCH OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
set(BUILD_TESTS OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
add_subdirectory(univalue)
target_compile_options(univalue PRIVATE -Wall -Wno-unused-parameter)

# BCHN modified sources, as a lib
add_library(bitcoin
    src/bitcoin/amount.cpp src/bitcoin/base58.cpp src/bitcoin/block.cpp src/bitcoin/bloom.cpp src/bitcoin/cashaddr.cpp src/bitcoin/cashaddrenc.cpp
    src/bitcoin/crypto/aes.cpp src/bitcoin/crypto/chacha20.cpp src/bitcoin/crypto/hmac_sha256.cpp src/bitcoin/crypto/hmac_sha512.cpp
    src/bitcoin/crypto/ripemd160.cpp src/bitcoin/crypto/sha1.cpp src/bitcoin/crypto/sha256.cpp src/bitcoin/crypto/sha256_sse4.cpp
    src/bitcoin/crypto/sha3.cpp src/bitcoin/crypto/sha512.cpp src/bitcoin/crypto/siphash.cpp src/bitcoin/feerate.cpp src/bitcoin/hash.cpp
    src/bitcoin/interpreter.cpp src/bitcoin/logging.cpp src/bitcoin/netaddress.cpp src/bitcoin/protocol.cpp src/bitcoin/pubkey.cpp
    src/bitcoin/random.cpp src/bitcoin/script.cpp src/bitcoin/script_error.cpp src/bitcoin/script_standard.cpp src/bitcoin/sigencoding.cpp
    src/bitcoin/token.cpp src/bitcoin/transaction.cpp src/bitcoin/uint256.cpp src/bitcoin/utilsaltedhashers.cpp
    src/bitcoin/utilstrencodings.cpp src/bitcoin/utilthreadnames.cpp src/bitcoin/utiltime.cpp
)

target_compile_definitions(bitcoin PRIVATE USE_ASM)
target_compile_options(bitcoin PRIVATE -Wall -Wno-unused-parameter)
if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
    message("Detected big endian platform")
    target_compile_definitions(bitcoin PRIVATE WORDS_BIGENDIAN)
endif()
target_link_libraries(bitcoin fmt::fmt)
# /BCHN

# Testing echoserver using asio
add_executable(asiotest src/asiotest.cpp src/util.cpp)
target_compile_options(asiotest PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(asiotest fmt::fmt asio::asio univalue bitcoin)

# bchp2p using asio
add_executable(bchp2p src/bchp2p.cpp src/util.cpp)
target_compile_options(bchp2p PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(bchp2p fmt::fmt asio::asio Boost::boost univalue bitcoin)

add_compile_definitions(VERSION_STR=\"${CMAKE_PROJECT_VERSION}\")

#include(GNUInstallDirs)
#install(TARGETS bchp2p
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#)
