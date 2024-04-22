cmake_minimum_required(VERSION 3.5)

set(CMAKE_USER_MAKE_RULES_OVERRIDE "${CMAKE_SOURCE_DIR}/cmake/modules/OverrideInitFlags.cmake")

project(bchp2p LANGUAGES CXX)

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

# AsyncIO
add_subdirectory(asyncio)
target_compile_options(asyncio PRIVATE -Wall -Wno-unused-parameter)

# UniValue
set(BUILD_BENCH OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
set(BUILD_TESTS OFF CACHE INTERNAL "Used by UniValue, disabled" FORCE)
add_subdirectory(univalue)
target_compile_options(univalue PRIVATE -Wall -Wno-unused-parameter)

# BCHN modified sources, as a lib
add_library(bitcoin
    bitcoin/amount.cpp bitcoin/base58.cpp bitcoin/block.cpp bitcoin/cashaddr.cpp bitcoin/cashaddrenc.cpp
    bitcoin/crypto/aes.cpp bitcoin/crypto/chacha20.cpp bitcoin/crypto/hmac_sha256.cpp bitcoin/crypto/hmac_sha512.cpp
    bitcoin/crypto/ripemd160.cpp bitcoin/crypto/sha1.cpp bitcoin/crypto/sha256.cpp bitcoin/crypto/sha256_sse4.cpp
    bitcoin/crypto/sha3.cpp bitcoin/crypto/sha512.cpp bitcoin/crypto/siphash.cpp bitcoin/hash.cpp
    bitcoin/interpreter.cpp bitcoin/logging.cpp bitcoin/netaddress.cpp bitcoin/protocol.cpp bitcoin/pubkey.cpp
    bitcoin/random.cpp bitcoin/script.cpp bitcoin/script_error.cpp bitcoin/script_standard.cpp bitcoin/sigencoding.cpp
    bitcoin/token.cpp bitcoin/transaction.cpp bitcoin/uint256.cpp bitcoin/utilsaltedhashers.cpp
    bitcoin/utilstrencodings.cpp bitcoin/utilthreadnames.cpp bitcoin/utiltime.cpp
)

target_compile_definitions(bitcoin PRIVATE USE_ASM)
target_compile_options(bitcoin PRIVATE -Wall -Wno-unused-parameter)
if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
    message("Detected big endian platform")
    target_compile_definitions(bitcoin PRIVATE WORDS_BIGENDIAN)
endif()
target_link_libraries(bitcoin fmt::fmt)
# /BCHN

# bchp2p using that tiny asyncio lib
add_executable(bchp2p_asyncio bchp2p_asyncio.cpp)
target_compile_options(bchp2p_asyncio PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(bchp2p_asyncio fmt::fmt asyncio univalue bitcoin)

# Testing echoserver using asio
add_executable(asiotest asiotest.cpp util.cpp)
target_compile_options(asiotest PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(asiotest fmt::fmt asio::asio univalue bitcoin)

# bchp2p using asio
add_executable(bchp2p_asio bchp2p_asio.cpp util.cpp)
target_compile_options(bchp2p_asio PRIVATE -Wall -Wno-unused-parameter)
target_link_libraries(bchp2p_asio fmt::fmt asio::asio univalue bitcoin)

#include(GNUInstallDirs)
#install(TARGETS bchp2p_asio bchp2p_asyncio
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#)
