// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (C) 2020 Tom Zander <tomz@freedommail.ch>
// Copyright (c) 2017-2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"

#include "hash.h"
#include "logging.h"

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>

#include <string.h> // for strnlen

namespace bitcoin {

static std::atomic<bool> g_initial_block_download_completed(false);

namespace NetMsgType {
using namespace std::string_view_literals;
const std::string_view VERSION = "version"sv;
const std::string_view VERACK = "verack"sv;
const std::string_view ADDR = "addr"sv;
const std::string_view ADDRV2 = "addrv2"sv;
const std::string_view SENDADDRV2 = "sendaddrv2"sv;
const std::string_view INV = "inv"sv;
const std::string_view GETDATA = "getdata"sv;
const std::string_view MERKLEBLOCK = "merkleblock"sv;
const std::string_view GETBLOCKS = "getblocks"sv;
const std::string_view GETHEADERS = "getheaders"sv;
const std::string_view TX = "tx"sv;
const std::string_view HEADERS = "headers"sv;
const std::string_view BLOCK = "block"sv;
const std::string_view GETADDR = "getaddr"sv;
const std::string_view MEMPOOL = "mempool"sv;
const std::string_view PING = "ping"sv;
const std::string_view PONG = "pong"sv;
const std::string_view NOTFOUND = "notfound"sv;
const std::string_view FILTERLOAD = "filterload"sv;
const std::string_view FILTERADD = "filteradd"sv;
const std::string_view FILTERCLEAR = "filterclear"sv;
const std::string_view REJECT = "reject"sv;
const std::string_view SENDHEADERS = "sendheaders"sv;
const std::string_view FEEFILTER = "feefilter"sv;
const std::string_view SENDCMPCT = "sendcmpct"sv;
const std::string_view CMPCTBLOCK = "cmpctblock"sv;
const std::string_view GETBLOCKTXN = "getblocktxn"sv;
const std::string_view BLOCKTXN = "blocktxn"sv;
const std::string_view EXTVERSION = "extversion"sv;
const std::string_view DSPROOF = "dsproof-beta"sv;

bool IsBlockLike(std::string_view msg_type) {
    return msg_type == NetMsgType::BLOCK ||
           msg_type == NetMsgType::CMPCTBLOCK ||
           msg_type == NetMsgType::BLOCKTXN;
}
std::string_view Normalize(std::string_view msg_type) {
    for (const auto &mt : getAllNetMessageTypes())
        if (mt == msg_type) return mt; // assumption is `mt` outlives everything in this program
    return "Unknown"sv;
}
}; // namespace NetMsgType

/**
 * All known message types. Keep this in the same order as the list of messages
 * above and in protocol.h.
 */
static const std::vector<std::string_view> allNetMessageTypesVec{{
    NetMsgType::VERSION,     NetMsgType::VERACK,     NetMsgType::ADDR,        NetMsgType::ADDRV2,
    NetMsgType::SENDADDRV2,  NetMsgType::INV,        NetMsgType::GETDATA,     NetMsgType::MERKLEBLOCK,
    NetMsgType::GETBLOCKS,   NetMsgType::GETHEADERS, NetMsgType::TX,          NetMsgType::HEADERS,
    NetMsgType::BLOCK,       NetMsgType::GETADDR,    NetMsgType::MEMPOOL,     NetMsgType::PING,
    NetMsgType::PONG,        NetMsgType::NOTFOUND,   NetMsgType::FILTERLOAD,  NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR, NetMsgType::REJECT,     NetMsgType::SENDHEADERS, NetMsgType::FEEFILTER,
    NetMsgType::SENDCMPCT,   NetMsgType::CMPCTBLOCK, NetMsgType::GETBLOCKTXN, NetMsgType::BLOCKTXN,
    NetMsgType::EXTVERSION,  NetMsgType::DSPROOF,
}};

CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn) {
    // Copy magic
    std::memcpy(pchMessageStart.data(), pchMessageStartIn.data(), MESSAGE_START_SIZE);
    std::memset(pchCommand.data(), 0, pchCommand.size());
    nMessageSize = -1;
    std::memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn,
                               std::string_view command,
                               unsigned int nMessageSizeIn) {
    // Copy magic
    std::memcpy(pchMessageStart.data(), pchMessageStartIn.data(), MESSAGE_START_SIZE);
    // Assert that the command name passed in is not longer than COMMAND_SIZE
    assert(command.size() <= COMMAND_SIZE);
    // Copy the command name
    std::memcpy(pchCommand.data(), command.data(), std::min(pchCommand.size(), command.size()));
    // Zero-pad to COMMAND_SIZE bytes
    if (pchCommand.size() > command.size()) {
        std::memset(pchCommand.data() + command.size(), 0, pchCommand.size() - command.size());
    }

    nMessageSize = nMessageSizeIn;
    std::memset(pchChecksum, 0, CHECKSUM_SIZE);
}
CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn, const CSerializedNetMsg &msg)
    : CMessageHeader(pchMessageStartIn, msg.m_type, msg.data.size())
{
    const uint256 hash = Hash(Span{msg.data}.first(nMessageSize));
    std::memcpy(pchChecksum, hash.data(), CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const {
    return std::string(pchCommand.data(), pchCommand.data() + strnlen(pchCommand.data(), pchCommand.size()));
}

static bool
CheckHeaderMagicAndCommand(const CMessageHeader &header, const CMessageHeader::MessageMagic &magic) {
    // Check start string
    if (std::memcmp(std::begin(header.pchMessageStart), std::begin(magic), CMessageHeader::MESSAGE_START_SIZE) != 0) {
        return false;
    }

    // Check the command string for errors
    const char * const end = header.pchCommand.data() + header.pchCommand.size();
    for (const char *p1 = header.pchCommand.data(); p1 < end; ++p1) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < end; ++p1) {
                if (*p1 != 0) {
                    return false;
                }
            }
        } else if (*p1 < ' ' || *p1 > 0x7E) {
            return false;
        }
    }

    return true;
}

bool CMessageHeader::IsValid(const MessageMagic &magic) const {
    // Check start string
    if (!CheckHeaderMagicAndCommand(*this, magic)) {
        return false;
    }

    // Message size
    if (IsOversized()) {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) is oversized\n", GetCommand(), nMessageSize);
        return false;
    }

    return true;
}

bool CMessageHeader::IsOversized() const {
    // If the message doesn't not contain a block content, check against MAX_PROTOCOL_MESSAGE_LENGTH.
    if (nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH && !NetMsgType::IsBlockLike(GetCommand())) {
        return true;
    }

    // Modified by Calin: 2GiB
    if (nMessageSize > 0x7f'ff'ff'ff) {
        return true;
    }

    return false;
}

ServiceFlags GetDesirableServiceFlags(ServiceFlags services) {
    if ((services & NODE_NETWORK_LIMITED) && g_initial_block_download_completed) {
        return ServiceFlags(NODE_NETWORK_LIMITED);
    }
    return ServiceFlags(NODE_NETWORK);
}

void SetServiceFlagsIBDCache(bool state) {
    g_initial_block_download_completed = state;
}

std::string CInv::GetCommand() const {
    std::string cmd;
    switch (GetKind()) {
        case MSG_TX:
            return cmd.append(NetMsgType::TX);
        case MSG_BLOCK:
            return cmd.append(NetMsgType::BLOCK);
        case MSG_FILTERED_BLOCK:
            return cmd.append(NetMsgType::MERKLEBLOCK);
        case MSG_CMPCT_BLOCK:
            return cmd.append(NetMsgType::CMPCTBLOCK);
        case MSG_DOUBLESPENDPROOF:
             return cmd.append(NetMsgType::DSPROOF);
        default:
            throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const {
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch (const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::vector<std::string_view> &getAllNetMessageTypes() {
    return allNetMessageTypesVec;
}

} // namespace bitcoin
