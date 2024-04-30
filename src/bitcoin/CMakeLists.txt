project(bitcoin LANGUAGES CXX VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckCXXSourceCompiles)

# Endianness
check_include_files("endian.h" HAVE_ENDIAN_H)
check_include_files("sys/endian.h" HAVE_SYS_ENDIAN_H)

if(HAVE_ENDIAN_H)
    set(ENDIAN_FILE "endian.h")
elseif(HAVE_SYS_ENDIAN_H)
    set(ENDIAN_FILE "sys/endian.h")
else()
endif()

if(ENDIAN_FILE)
    check_symbol_exists(htole16 ${ENDIAN_FILE} HAVE_DECL_HTOLE16)
    check_symbol_exists(htobe16 ${ENDIAN_FILE} HAVE_DECL_HTOBE16)
    check_symbol_exists(be16toh ${ENDIAN_FILE} HAVE_DECL_BE16TOH)
    check_symbol_exists(le16toh ${ENDIAN_FILE} HAVE_DECL_LE16TOH)
    check_symbol_exists(htobe32 ${ENDIAN_FILE} HAVE_DECL_HTOBE32)
    check_symbol_exists(htole32 ${ENDIAN_FILE} HAVE_DECL_HTOLE32)
    check_symbol_exists(be32toh ${ENDIAN_FILE} HAVE_DECL_BE32TOH)
    check_symbol_exists(le32toh ${ENDIAN_FILE} HAVE_DECL_LE32TOH)
    check_symbol_exists(htobe64 ${ENDIAN_FILE} HAVE_DECL_HTOBE64)
    check_symbol_exists(htole64 ${ENDIAN_FILE} HAVE_DECL_HTOLE64)
    check_symbol_exists(be64toh ${ENDIAN_FILE} HAVE_DECL_BE64TOH)
    check_symbol_exists(le64toh ${ENDIAN_FILE} HAVE_DECL_LE64TOH)
endif()

# Byte swap
check_include_files("byteswap.h" HAVE_BYTESWAP_H)

check_symbol_exists(bswap_16 "byteswap.h" HAVE_DECL_BSWAP_16)
check_symbol_exists(bswap_32 "byteswap.h" HAVE_DECL_BSWAP_32)
check_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)

# sys/select.h and sys/prctl.h headers
check_include_files("sys/select.h" HAVE_SYS_SELECT_H)
check_include_files("sys/prctl.h" HAVE_SYS_PRCTL_H)

# Bitmanip intrinsics
function(check_builtin_exist SYMBOL VARIABLE)
    set(
        SOURCE_FILE
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/CheckBuiltinExists.c"
    )
    set(
        CMAKE_CONFIGURABLE_FILE_CONTENT
        "int main(int argc, char** argv) { (void)argv; return ${SYMBOL}(argc); }\n"
    )
    configure_file(
        "${CMAKE_ROOT}/Modules/CMakeConfigurableFile.in"
        "${SOURCE_FILE}"
        @ONLY
    )
    if(NOT CMAKE_REQUIRED_QUIET)
        message(STATUS "Looking for ${SYMBOL}")
    endif()
    try_compile(${VARIABLE}
        ${CMAKE_BINARY_DIR}
        ${SOURCE_FILE}
        OUTPUT_VARIABLE OUTPUT
    )
    if(${VARIABLE})
        if(NOT CMAKE_REQUIRED_QUIET)
            message(STATUS "Looking for ${SYMBOL} - found")
        endif()
        set(${VARIABLE} 1 CACHE INTERNAL "Have symbol ${SYMBOL}" PARENT_SCOPE)
        file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
            "Determining if the ${SYMBOL} "
            "exist passed with the following output:\n"
            "${OUTPUT}\nFile ${SOURCEFILE}:\n"
            "${CMAKE_CONFIGURABLE_FILE_CONTENT}\n")
    else()
        if(NOT CMAKE_REQUIRED_QUIET)
            message(STATUS "Looking for ${SYMBOL} - not found")
        endif()
        set(${VARIABLE} "" CACHE INTERNAL "Have symbol ${SYMBOL}" PARENT_SCOPE)
        file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
            "Determining if the ${SYMBOL} "
            "exist failed with the following output:\n"
            "${OUTPUT}\nFile ${SOURCEFILE}:\n"
            "${CMAKE_CONFIGURABLE_FILE_CONTENT}\n")
    endif()
endfunction()

check_builtin_exist(__builtin_clz HAVE_DECL___BUILTIN_CLZ)
check_builtin_exist(__builtin_clzl HAVE_DECL___BUILTIN_CLZL)
check_builtin_exist(__builtin_clzll HAVE_DECL___BUILTIN_CLZLL)
check_builtin_exist(__builtin_popcount HAVE_DECL___BUILTIN_POPCOUNT)

# Memory management capabilities
check_symbol_exists(M_ARENA_MAX "malloc.h" HAVE_MALLOPT_ARENA_MAX)
check_symbol_exists(malloc_info "malloc.h" HAVE_MALLOC_INFO)

# Various system libraries
check_symbol_exists(strnlen "string.h" HAVE_DECL_STRNLEN)
# daemon() is located in unistd.h on linux and in stdlib.h on BSDs and macOS.
check_symbol_exists(daemon "unistd.h;stdlib.h" HAVE_DECL_DAEMON)

# Check for ways to obtain entropy
check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
# macOS needs unistd.h and sys/random.h to define getentropy
check_symbol_exists(getentropy "unistd.h;sys/random.h" HAVE_GETENTROPY_RAND)

# getifaddrs and freeifaddrs may be unavailable with some Android versions
check_symbol_exists(getifaddrs "sys/types.h;ifaddrs.h" HAVE_DECL_GETIFADDRS)
check_symbol_exists(freeifaddrs "sys/types.h;ifaddrs.h" HAVE_DECL_FREEIFADDRS)

check_cxx_source_compiles("
    #include <unistd.h>  /* for syscall */
    #include <sys/syscall.h>  /* for SYS_getrandom */
    #include <linux/random.h>
    int main() {
        syscall(SYS_getrandom, nullptr, 0, 0);
        return 0;
    }
" HAVE_SYS_GETRANDOM)

check_cxx_source_compiles("
    #include <sys/types.h>
    #include <sys/sysctl.h>
    int main() {
        static const int name[2] = {CTL_KERN, KERN_ARND};
        sysctl(name, 2, nullptr, nullptr, nullptr, 0);
        return 0;
    }
" HAVE_SYSCTL_ARND)

check_cxx_source_compiles("
    #include <cstdint>
    #include <type_traits>
    int main() {
        static_assert(std::is_same<int8_t, char>::value, \"\");
        return 0;
    }
" CHAR_EQUALS_INT8)

check_cxx_source_compiles("
    #include <sys/types.h>
    #include <type_traits>
    int main() {
        static_assert(sizeof(off_t) == 8, \"\");
        return 0;
    }
" HAVE_LARGE_FILE_SUPPORT)

check_cxx_source_compiles("
    __attribute__((visibility(\"default\"))) int main() {
        return 0;
    }
" HAVE_FUNC_ATTRIBUTE_VISIBILITY)

check_cxx_source_compiles("
    __declspec(dllexport) int main() {
        return 0;
    }
" HAVE_FUNC_ATTRIBUTE_DLLEXPORT)

check_cxx_source_compiles("
    #include <cstdint>

    int main() {
        using u128 = unsigned __int128;
        u128 val = 42;
        return (val * val) / (42 * 42) - 1;
    }
" HAVE_INT128)

# Generate the config
configure_file(config/bitcoin-config.h.cmake.in config/bitcoin-config.h ESCAPE_QUOTES)

add_library(bitcoin
    amount.cpp
    base58.cpp
    block.cpp
    bloom.cpp
    cashaddr.cpp
    cashaddrenc.cpp
    crypto/aes.cpp
    crypto/chacha20.cpp
    crypto/hmac_sha256.cpp
    crypto/hmac_sha512.cpp
    crypto/ripemd160.cpp
    crypto/sha1.cpp
    crypto/sha256.cpp
    crypto/sha256_sse4.cpp
    crypto/sha3.cpp
    crypto/sha512.cpp
    crypto/siphash.cpp
    feerate.cpp
    hash.cpp
    interpreter.cpp
    logging.cpp
    netaddress.cpp
    protocol.cpp
    pubkey.cpp
    random.cpp
    script.cpp
    script_error.cpp
    script_standard.cpp
    sigencoding.cpp
    token.cpp
    transaction.cpp
    uint256.cpp
    utilsaltedhashers.cpp
    utilstrencodings.cpp
    utilthreadnames.cpp
    utiltime.cpp
)

# Libformat
find_package(fmt REQUIRED)

target_compile_definitions(bitcoin PUBLIC HAVE_BITCOIN_CONFIG_H)

# Ensure #include <bitcoin-config.h> works
target_include_directories(bitcoin PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/config)

target_compile_definitions(bitcoin PRIVATE USE_ASM)
target_compile_options(bitcoin PRIVATE -Wall -Wno-unused-parameter)
if(CMAKE_CXX_BYTE_ORDER STREQUAL "BIG_ENDIAN")
    message("Detected big endian platform")
    target_compile_definitions(bitcoin PRIVATE WORDS_BIGENDIAN)
endif()
target_link_libraries(bitcoin fmt::fmt)
