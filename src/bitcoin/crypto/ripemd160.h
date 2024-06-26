// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <cstdlib>

namespace bitcoin {

/** A hasher class for RIPEMD-160. */
class CRIPEMD160 {
private:
    uint32_t s[5];
    uint8_t buf[64];
    uint64_t bytes;

public:
    static constexpr size_t OUTPUT_SIZE = 20;

    CRIPEMD160();
    CRIPEMD160 &Write(const uint8_t *data, size_t len);
    void Finalize(uint8_t hash[OUTPUT_SIZE]);
    CRIPEMD160 &Reset();
};

} // end namespace bitcoin
