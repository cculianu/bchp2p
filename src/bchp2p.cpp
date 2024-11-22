#include "bitcoin/block.h"
#include "bitcoin/bloom.h"
#include "bitcoin/crypto/sha256.h"
#include "bitcoin/feerate.h"
#include "bitcoin/hash.h"
#include "bitcoin/logging.h"
#include "bitcoin/protocol.h"
#include "bitcoin/random.h"
#include "bitcoin/streams.h"
#include "bitcoin/sync.h"
#include "bitcoin/random.h"
#include "bitcoin/utilsaltedhashers.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin/utilthreadnames.h"
#include "bitcoin/utiltime.h"

#include "argparse.hpp"
#include "html_bits.h"
#include "util.h"

#include <asio.hpp>
#include <asio/experimental/channel.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/range/adaptors.hpp>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <server_http.hpp>
#include <univalue.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

using asio::ip::tcp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using chan_void = asio::experimental::channel<void()>;
namespace this_coro = asio::this_coro;

template <typename T = void, typename E = asio::any_io_executor>
using async = awaitable<T, E>; // make it look a little more like Python? ;)

/// Keeps `context` object alive for as long as this task is alive, by retaining a shared_ptr to it.
template <typename Ctx, typename Completion, typename T = void, typename E = asio::any_io_executor>
void co_spawn_shared(const std::enable_shared_from_this<Ctx> &context, const asio::any_io_executor &executor,
                     async<T, E> && task, Completion && token) {
    co_spawn(executor, [&]() -> async<T, E>{
        auto shared = context.shared_from_this(); // keep `context` alive for as long as this task is alive
        co_return co_await std::move(task);
    }(), std::forward<Completion>(token));
}

using namespace std::string_view_literals;

using bitcoin::CBlock;
using bitcoin::CTransactionRef;
using bitcoin::DebugLock;
using bitcoin::DebugSharedLock;
using bitcoin::Mutex;
using bitcoin::SharedMutex;
using bitcoin::Tic;
using bitcoin::uint256;
using bitcoin::uint256S;

namespace {

struct ProtocolError : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class Connection;

struct ChainParams
{
    std::string_view name;
    bitcoin::CMessageHeader::MessageMagic netMagic;
    std::pair<uint32_t, uint256> mostRecentCheckpoint;
};

enum Net : uint8_t { Main = 0, Chip, Test3, Test4, Scale, Reg, BtcMain, BtcTest3, BtcTest4,
                     NumNets, AnyNet = 0xffu /* special value! */ };

const std::array<ChainParams, NumNets> netChainParams = {
    // NB: these should be in the same order as the `Net` enum above
    ChainParams{ .name = "Main", .netMagic = {0xe3, 0xe1, 0xf3, 0xe8},
                 .mostRecentCheckpoint = {847'762,   uint256S("0000000000000000010d0029ada78decbe529c1376ffc43466a28f5e585753ce")}},
    ChainParams{ .name = "Chip", .netMagic = {0xe2, 0xb7, 0xda, 0xaf},
                 .mostRecentCheckpoint = {200'607,   uint256S("000000005b2192ec61f1089479ab90993896e31642ba24ae6948f913084c5ea5")}},
    ChainParams{ .name = "Test3", .netMagic = {0xf4, 0xe5, 0xf3, 0xf4},
                 .mostRecentCheckpoint = {1'605'521, uint256S("000000000000007d4c561056e9bcb3ab7591d024b18fff4bc27cca4d51d4780e")}},
    ChainParams{ .name = "Test4", .netMagic = {0xe2, 0xb7, 0xda, 0xaf},
                 .mostRecentCheckpoint = {200'741,   uint256S("0000000007d8ccbb767c269551dd81c520463066bec8654a18f4106aa53dc816")}},
    ChainParams{ .name = "Scale", .netMagic = {0xc3, 0xaf, 0xe1, 0xa2},
                 .mostRecentCheckpoint = {10'000,    uint256S("00000000b711dc753130e5083888d106f99b920b1b8a492eb5ac41d40e482905")}},
    ChainParams{ .name = "Reg",   .netMagic = {0xda, 0xb5, 0xbf, 0xfa},
                 .mostRecentCheckpoint = {0,         uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")}},
    /* BTC */
    ChainParams{ .name = "BtcMain",  .netMagic = {0xf9, 0xbe, 0xb4, 0xd9},
                 .mostRecentCheckpoint = {840'000,   uint256S("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5")}},
    ChainParams{ .name = "BtcTest3", .netMagic = {0x0b, 0x11, 0x09, 0x07},
                 .mostRecentCheckpoint = {2'500'000, uint256S("0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f")}},
    ChainParams{ .name = "BtcTest4", .netMagic = {0x1c, 0x16, 0x3f, 0x28},
                .mostRecentCheckpoint = {50'000,     uint256S("00000000e2c8c94ba126169a88997233f07a9769e2b009fb10cad0e893eff2cb")}},
};

std::string_view Net2Name(Net net) {
    if (size_t(net) < netChainParams.size()) return netChainParams[size_t(net)].name;
    else if (net == Net::AnyNet) return "*Any*"sv;
    return ""sv;
}

std::optional<Net> Name2Net(std::string_view name, bool caseSensitive = false) {
    if (caseSensitive) {
        for (size_t i = 0; i < netChainParams.size(); ++i)
            if (name == netChainParams[i].name) return Net(i);
        if (name == "*Any*"sv) return Net::AnyNet;
    } else {
        for (size_t i = 0; i < netChainParams.size(); ++i) {
            std::string lhs{name}, rhs{netChainParams[i].name};
            boost::algorithm::to_lower(lhs);
            boost::algorithm::to_lower(rhs);
            if (lhs == rhs) return Net(i);
        }
        if (std::string lhs{name}; boost::algorithm::to_lower(lhs), lhs == "*any*"sv) return Net::AnyNet;
    }
    return std::nullopt;
}

using Id = uint64_t;

inline Id GetNewId() {
    static std::atomic<Id> nextId = 1u;
    return nextId++;
}

struct ConnMgr
{
    mutable SharedMutex mut;
private:
    bitcoin::CRollingBloomFilter haveInvs GUARDED_BY(mut) {2'000'000, 0.0001};
    bitcoin::CRollingBloomFilter addrKnown GUARDED_BY(mut) {500'000, 0.001};
    size_t connsLost GUARDED_BY(mut) = 0u;
    std::atomic_size_t nInbound = 0u, nOutbound = 0u;
    std::map<Id, std::weak_ptr<Connection>> conns GUARDED_BY(mut);

    void add(std::weak_ptr<Connection>);
    void rm(Id connId);

    std::deque<bitcoin::CInv> invs2Spam GUARDED_BY(mut);

    struct FakeMempoolEntry {
        Tic tic;
        Net net;
        bool isSpamTxn = false;
        mutable std::atomic_uint32_t sendCt{0u};
        CTransactionRef tx;

        FakeMempoolEntry() = default;
        FakeMempoolEntry(const Tic &t, const Net n, const CTransactionRef &tx_, bool isSpam = false)
            : tic{t}, net{n}, isSpamTxn{isSpam}, tx{tx_} {}
    };

    template <typename T>
    using Ref = std::reference_wrapper<T>;

    std::unordered_map<Ref<const uint256>, FakeMempoolEntry, bitcoin::SaltedUint256Hasher>
        fakeMempool GUARDED_BY(mut);

    std::tuple<CTransactionRef, std::atomic_uint32_t *, bool>
    GetTxn_nolock(const Net net, const uint256 &txid) const SHARED_LOCKS_REQUIRED(mut) {
        if (auto it = fakeMempool.find(txid); it != fakeMempool.end())
            if (net == Net::AnyNet || it->second.net == Net::AnyNet || it->second.net == net)
                return {it->second.tx, &it->second.sendCt, it->second.isSpamTxn};
        return {{}, nullptr, false};
    }

    std::pair<bool, size_t>
    AddTxnToFakeMempool_nolock(Net net, const CTransactionRef &tx, bool pushInvs, bool isSpam = false)
        EXCLUSIVE_LOCKS_REQUIRED(mut);

public:
    ConnMgr(std::vector<CTransactionRef> txns2Spam = {});
    ~ConnMgr();

    /// Creates a new Connection object. `sock` should be an newly connected socket.
    std::shared_ptr<Connection> CreateConnection(tcp::socket &&sock, bool inbound, Net net, std::string_view infoName);

    std::shared_ptr<asio::io_context> io_context = std::make_shared<asio::io_context>(1);
    std::atomic_size_t nServers = 0u;

    bool haveInv_nolock(const uint256 &invHash) const SHARED_LOCKS_REQUIRED(mut) {
        return haveInvs.contains(invHash);
    }

    bool haveInv(const uint256 &invHash) const {
        LOCK_SHARED(mut);
        return haveInv_nolock(invHash);
    }

    void setHaveInv(const uint256 &inv) {
        LOCK(mut);
        haveInvs.insert(inv);
    }

    bool isAddrKnown_nolock(const bitcoin::CAddress &addr) const {
        return addrKnown.contains(addr.GetKey());
    }

    bool isAddrKnown(const bitcoin::CAddress &addr) const {
        LOCK_SHARED(mut);
        return isAddrKnown_nolock(addr);
    }

    void addAddrKnown(std::span<const bitcoin::CAddress *> addrs) {
        LOCK(mut);
        for (auto * addr : addrs)
            addrKnown.insert(addr->GetKey());
    }

    UniValue::Object GetStats() const;

    std::tuple<CTransactionRef, std::atomic_uint32_t *, bool> GetTxn(Net net, const uint256 &txid) const {
        LOCK_SHARED(mut);
        return GetTxn_nolock(net, txid);
    }

    std::vector<bitcoin::CInv> GetInvsToSpam(); /* intentionally non-const since it may clear/delete/maintain invs2Spam */

    std::pair<bool, size_t>
    AddTxnToFakeMempool(Net net, const CTransactionRef &tx, bool pushInvs = true, bool isSpam = false) {
        LOCK(mut);
        return AddTxnToFakeMempool_nolock(net, tx, pushInvs, false);
    }

    bool ProcessBlock(Net net, const uint256 &hash, std::shared_ptr<const CBlock> pblk) {
        if (!pblk) return false;
        LOCK(mut);
        if (haveInv_nolock(hash)) return false;
        haveInvs.insert(hash);
        size_t nRemoved{};
        auto & blk = *pblk;
        for (const auto &tx : blk.vtx) {
            if (auto it = fakeMempool.find(tx->GetHashRef());
                    it != fakeMempool.end() && (it->second.net == net || it->second.net == Net::AnyNet)) {
                fakeMempool.erase(it);
                ++nRemoved;
            }
        }
        if (nRemoved) Log("{}: Removed {} txns from fakeMempool that appear in block {}, poolsz now: {}",
                          __func__, nRemoved, hash.ToString(), fakeMempool.size());
        return true;
    }

    void Cancel() {
        if (!cancelled) {
            Debug(Color::bright_black, "ConnMgr: Canceling processing ...");
            cancelled = true;
            cleaner.cancel();
        }
    }

    void Start();

private:
    asio::steady_timer cleaner{*io_context};
    bool cancelled = false, started = false;

    async<> cleanFakeMempool();
};

ConnMgr::ConnMgr(std::vector<CTransactionRef> txns2Spam) {
    Start();

    LOCK(mut);
    for (const auto &tx : txns2Spam)
        if (AddTxnToFakeMempool_nolock(Net::AnyNet, tx, false, true).first)
            invs2Spam.emplace_back(bitcoin::MSG_TX, tx->GetHashRef());
}

ConnMgr::~ConnMgr() {
    Cancel();
    Debug(Color::bright_black, "~ConnMgr");
}

void ConnMgr::Start() {
    if (!started) {
        started = true;
        co_spawn(io_context->get_executor(), cleanFakeMempool(), detached);
    }
}

async<> ConnMgr::cleanFakeMempool()
{
    Debug("{}: started", __func__);
    Defer d([f=std::string_view{__func__}]{ Debug("{}: stopped", f); });
    constexpr int cleanTime = 30 * 60; /* 30 mins */
    while (!cancelled) {
        cleaner.expires_from_now(std::chrono::seconds{cleanTime / 2});
        co_await cleaner.async_wait(use_awaitable);
        if (cancelled) co_return;
        Debug("{}: wakeup", __func__);
        size_t nDeleted = 0;
        {
            LOCK(mut);
            for (auto it = fakeMempool.begin(); it != fakeMempool.end(); /**/) {
                if (it->second.tic.secs<int64_t>() >= cleanTime && (!it->second.isSpamTxn || it->second.sendCt > 0u)) {
                    it = fakeMempool.erase(it);
                    ++nDeleted;
                } else
                    ++it;
            }
        }
        if (nDeleted) {
            const size_t oldSz = invs2Spam.size();
            const size_t newSz = GetInvsToSpam().size(); // this implicitly "cleans" the invs2Spam deque
            Log("{}: deleted {} txns{} from the fake mempool that are older than {} seconds", __func__, nDeleted,
                newSz < oldSz ? fmt::format(" (including {} invs2Spam txs)", oldSz - newSz) : std::string{},
                cleanTime);

        }
    }
}

std::vector<bitcoin::CInv> ConnMgr::GetInvsToSpam() {
    std::vector<bitcoin::CInv> ret;
    {
        LOCK(mut);
        ret.reserve(invs2Spam.size());
        for (auto it = invs2Spam.begin(); it != invs2Spam.end(); /**/)
            if (const auto &inv = *it; inv.IsTx() && fakeMempool.find(inv.hash) != fakeMempool.end())
                // still exists, add
                ret.push_back(inv), ++it;
            else
                // was cleaned.. delete
                it = invs2Spam.erase(it);
    }
    return ret;
}


class Connection : public std::enable_shared_from_this<Connection>
{
    ConnMgr * const mgr;
    const Id id = GetNewId();
    tcp::socket sock;
    chan_void write_lock;
    bitcoin::CAddress local, remote;
    const bool inbound;
    const Net net;
    const ChainParams &params;
    std::string infoName;
    const uint64_t nLocalNonce;
    bitcoin::Tic tstart;
    bool disconnectRequested = false, pingerScheduled = false, cleanerScheduled = false, didScheduleInvSender = false;
    bitcoin::CRollingBloomFilter peerHasInvs {750'000, 0.0001};

    std::map<std::string_view, size_t> msgByteCountsIn, msgByteCountsOut, msgCountsIn{}, msgCountsOut{};
    size_t bytesIn{}, bytesOut{}, msgsIn{}, msgsOut{};

    int protoVersion = bitcoin::INIT_PROTO_VERSION;
    std::string cleanSubVer;
    bool sentVersion = false, sentVerAck = false, gotVersion = false, gotVerAck = false, didAfterHandshake = false, didVerifyCheckPoint = false;
    bool relay = false;
    int misbehavior = 0;
    int startingHeight = -1; // remote starting height
    static constexpr int MAX_MISBEHAVIOR = 100;
    bitcoin::Amount feeFilter;

    std::unordered_map<uint256, int64_t, bitcoin::SaltedUint256Hasher> requestedInvs;
    std::deque<bitcoin::CInv> invQ;

    [[nodiscard]]
    async<> MsgHandler(bitcoin::CSerializedNetMsg && msg);

    [[nodiscard]] async<> SendVersion();
    [[nodiscard]] async<> SendVerACK(int nVersion = 0);
    [[nodiscard]] async<> Send(bitcoin::CSerializedNetMsg msg);
    template <typename ...Args>
    [[nodiscard]] async<> Send(int protocol_version, std::string_view msg_type, Args ...args) {
        using namespace bitcoin;
        co_await Send(CNetMsgMaker(protocol_version).Make(msg_type, std::forward<Args>(args)...));
    }
    template <typename ...Args>
    [[nodiscard]] async<> Send(std::string_view msg_type, Args ...args) {
        co_await Send(protoVersion, msg_type, std::forward<Args>(args)...);
    }

    bitcoin::VectorReader MakeReader(const bitcoin::CSerializedNetMsg &msg, int protoFlags = 0, size_t pos = 0) const {
        using namespace bitcoin;
        return VectorReader(SER_NETWORK, protoVersion | protoFlags, msg.data, pos);
    }

    [[nodiscard]] async<> HandleVersion(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandlePing(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandlePong(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleInvs(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleTx(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleBlock(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleFeeFilter(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleAddr(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleHeaders(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleReject(bitcoin::CSerializedNetMsg && msg);
    [[nodiscard]] async<> HandleGetData(bitcoin::CSerializedNetMsg && msg);

    [[nodiscard]] async<> DoOnceIfAfterHandshake(); // does GETADDR, etc -- stuff we do immediately after a state change to "fully established"
    [[nodiscard]] async<> InvSender();

    static constexpr int pingIntervalSecs = 30;
    uint64_t lastPingNonceSent = 0;
    int64_t lastPingTSMillis = 0, lastPongTSMillis = 0, lastPingPongDelta = 0;
    [[nodiscard]] async<> Pinger(); // periodically pings node every 30 seconds

    static constexpr int cleanIntervalSecs = 60;
    [[nodiscard]] async<> Cleaner(); // periodically does cleanup

    std::string GetInfoStr() const {
        // this is a hack
        return fmt::format("{}{} ({})", inbound ? "[inbound] " : "",
                           infoName.empty() ? remote.ToStringIPPort() : GetName(),
                           params.name);
    }

    void Misbehaving(int score, std::string_view msg);

    asio::steady_timer pinger, cleaner, invSendTimer;

    [[nodiscard]]
    async<> CancelProcessing() {
        Debug("{}: Canceling processing ...\n", GetInfoStr());
        disconnectRequested = true;
        asio::error_code ec{};
        pinger.cancel(ec);
        cleaner.cancel(ec);
        write_lock.cancel();
        invSendTimer.cancel(ec);
        Debug("{}: shutdown ...\n", GetInfoStr());
        sock.shutdown(sock.shutdown_both, ec);
        auto e = co_await this_coro::executor;
        asio::steady_timer t(e);
        t.expires_from_now(std::chrono::milliseconds{10});
        co_await t.async_wait(use_awaitable);
        Debug("{}: close ...\n", GetInfoStr());
        sock.close(ec);
        sock.cancel(ec);
    }

    void scheduleDisconnect() {
        if (!disconnectRequested) {
            disconnectRequested = true;
            co_spawn_shared(*this, sock.get_executor(), CancelProcessing(), detached);
        }
    }

    void schedulePinger() {
        if (!pingerScheduled) {
            pingerScheduled = true;
            co_spawn_shared(*this, sock.get_executor(), Pinger(), detached);
        }
    }

    void scheduleCleaner() {
        if (!cleanerScheduled) {
            cleanerScheduled = true;
            co_spawn_shared(*this, sock.get_executor(), Cleaner(), detached);
        }
    }

    void scheduleInvSender() {
        if (!didScheduleInvSender) {
            didScheduleInvSender = true;
            co_spawn_shared(*this, sock.get_executor(), InvSender(), detached);
        }
    }

    unsigned GetCheckpointHeight() const {
        return !params.mostRecentCheckpoint.second.IsNull() ? params.mostRecentCheckpoint.first : 0;
    }

    const uint256 & GetCheckpointHash() const { return params.mostRecentCheckpoint.second; }

protected:
    friend ConnMgr;
    Connection(ConnMgr *mgr, tcp::socket &&sock_, bool inbound_, Net net_, std::string_view infoName_)
        : mgr(mgr), sock(std::move(sock_)), write_lock(sock.get_executor(), 1), inbound(inbound_), net(net_),
          params(netChainParams.at(net)), infoName(infoName_), nLocalNonce(bitcoin::GetRand64()),
          pinger(sock.get_executor()), cleaner(sock.get_executor()), invSendTimer(sock.get_executor())
    {
        bitcoin::CService srv;
        auto ep2srv = [](const tcp::endpoint &ep) {
            if (auto a = ep.address(); a.is_v4()) {
                struct in_addr const inaddr { .s_addr = std::bit_cast<in_addr_t>(a.to_v4().to_bytes()) };
                return bitcoin::CService(inaddr, ep.port());
            } else if (a.is_v6()) {
                struct in6_addr const in6addr = std::bit_cast<struct in6_addr>(a.to_v6().to_bytes());
                return bitcoin::CService(in6addr, ep.port());
            } else [[unlikely]] {
                throw std::runtime_error("unknown address type in Connection::Connection");
            }
        };
        srv = ep2srv(sock.local_endpoint());
        local = bitcoin::CAddress(srv, bitcoin::ServiceFlags(bitcoin::NODE_BITCOIN_CASH|bitcoin::NODE_NETWORK|bitcoin::NODE_BLOOM),
                                  bitcoin::GetTime());
        srv = ep2srv(sock.remote_endpoint());
        remote = bitcoin::CAddress(srv, bitcoin::ServiceFlags::NODE_NONE, bitcoin::GetTime());
        if (infoName.empty()) infoName = remote.ToStringIP();
    }

public:
    // NB: Use ConnMgr to Constructs a new instance (ensures it's wrapped in a shared_ptr)

    Connection(Connection &&) = delete;

    ~Connection() { Debug(Color::bright_black, "{}: ~Connection", GetInfoStr()); }

    [[nodiscard]]
    async<> ProcessLoop();

    bool isFullyConnected() const { return sentVersion && sentVerAck && gotVersion && gotVerAck; }

    std::string GetName() const { return fmt::format("{}:{}", !infoName.empty() ? infoName : "???", remote.ToStringPort()); }

    UniValue::Object GetStats() const;

    Id GetId() const { return id; }

    bool IsInbound() const { return inbound; }

    Net GetNet() const { return net; }

    void PushInv(bitcoin::GetDataMsg type, const uint256 &hash);
};

std::shared_ptr<Connection> ConnMgr::CreateConnection(tcp::socket &&sock, bool inbound, Net net, std::string_view infoName = {})
{
    Connection *conn = new Connection(this, std::move(sock), inbound, net, infoName);
    Defer d([&conn] { if (conn) { delete conn; conn = nullptr; } }); // ensure `conn` doesn't leak on exception
    std::shared_ptr<Connection> ret(conn, [this](Connection *c) { rm(c->GetId()); delete c; });
    conn = nullptr;
    add(ret);
    return ret;
}

void ConnMgr::add(std::weak_ptr<Connection> wc) {
    auto c = wc.lock();
    assert(bool(c));
    LOCK(mut);
    auto const & [it, inserted] = conns.try_emplace(c->GetId(), wc);
    assert(inserted);
    if (c->IsInbound()) ++nInbound;
    else ++nOutbound;
}

void ConnMgr::rm(Id id) {
    LOCK(mut);
    auto const n = conns.erase(id);
    assert(n > 0u);
    connsLost += n;
    if (conns.empty() && !nServers) {
        io_context->stop();
    }
}

std::pair<bool, size_t>
ConnMgr::AddTxnToFakeMempool_nolock(Net net, const CTransactionRef &tx, bool pushInvs, bool isSpam) {
    const auto &txid = tx->GetHashRef();
    const auto & [it, inserted] = fakeMempool.try_emplace(std::ref(txid), Tic{}, net, tx, isSpam);
    if (inserted)  {
        haveInvs.insert(txid);
        if (pushInvs) {
            for (const auto & [id, wptr] : conns) {
                auto conn = wptr.lock();
                if (!conn || (net != Net::AnyNet && conn->GetNet() != net) || conn->peerHasInvs.contains(tx->GetHashRef())) continue;
                conn->PushInv(bitcoin::MSG_TX, tx->GetHashRef());
            }
        }
    }
    return {inserted, fakeMempool.size()};
}

void Connection::PushInv(bitcoin::GetDataMsg type, const uint256 &hash)
{
    invQ.emplace_back(type, hash);
    invSendTimer.cancel_one();
}

async<> Connection::SendVersion()
{
    using namespace bitcoin;
    const int64_t nTime = static_cast<int64_t>(GetTime());
    const int64_t nLocalServices = local.nServices;
    const int nBestHeight = GetCheckpointHeight();
    const std::string ver = "/TestP2P:0.0.1/";
    const uint8_t fRelayTxs = 1;
    const CAddress addrMe = CAddress(CService(), ServiceFlags(nLocalServices));
    sentVersion = true;

    co_await Send(INIT_PROTO_VERSION, NetMsgType::VERSION, // cmd
                  PROTOCOL_VERSION, nLocalServices, nTime, remote, addrMe, nLocalNonce, ver, nBestHeight, fRelayTxs); // data
}

async<> Connection::SendVerACK(int nVersion)
{
    using namespace bitcoin;
    if (sentVerAck) co_return; // don't send it twice!
    sentVerAck = true;
    if (nVersion == 0) nVersion = protoVersion;
    if (nVersion >= FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION) {
        // Signal ADDRv2 support (BIP155), but only if version >= FEATURE_NEGOTIATION_BEFORE_VERACK_VERSION
        co_await Send(NetMsgType::SENDADDRV2);
    }
    co_await Send(NetMsgType::VERACK);
}

async<> Connection::Send(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    CMessageHeader hdr(params.netMagic, msg); // construct valid header with checksum
    std::vector<uint8_t> hdrData;
    hdrData.reserve(CMessageHeader::HEADER_SIZE);
    VectorWriter(SER_NETWORK, PROTOCOL_VERSION, hdrData, 0) << hdr;
    const size_t msgSize = hdrData.size() + msg.data.size();
    const auto cmd = hdr.GetCommand();
    Log("{}: Sending msg {} {} bytes\n", GetInfoStr(), cmd, msgSize);
    const auto ncmd = NetMsgType::Normalize(cmd); // assumption: Normalize() returns a long-lived string_view!
    msgByteCountsOut[ncmd] += msgSize;
    ++msgCountsOut[ncmd];
    bytesOut += msgSize;
    ++msgsOut;
    Tic t0;
    {
        // NB: We must do it this way to ensure serialized access to the socket.. using a channel to "fake" an async
        // mutex. Claim the write lock by sending a message to the channel. Since the channel signature is void(),
        // there are no arguments to send in the message itself.
        co_await write_lock.async_send(asio::deferred);
        co_await asio::async_write(sock, asio::buffer(hdrData), use_awaitable);
        co_await asio::async_write(sock, asio::buffer(msg.data), use_awaitable);
        // Release the lock by receiving the message back again.
        write_lock.try_receive([](auto...){});
    }
    Debug("{}: {} msec for '{}' xfer\n", GetInfoStr(), t0.msecStr(), ncmd);
}

async<> Connection::ProcessLoop()
{
    tstart = bitcoin::Tic();
    Log(Color::bright_green, "{}: Connection established\n", GetInfoStr());
    Defer d([&] {
        scheduleDisconnect();
        Log(Color::bright_green, "{}: ProcessLoop ended, {} secs elapsed\n", GetInfoStr(), tstart.secsStr(3));
    });
    if (!inbound) {
        // first thing we must do is send the version
        co_await SendVersion();
    }
    using namespace bitcoin;
    using Hdr = CMessageHeader;
    try {
        co_await this_coro::throw_if_cancelled(true);
        while ( ! disconnectRequested) {
            std::array<uint8_t, Hdr::HEADER_SIZE> headerbuf;
            auto nread = co_await asio::async_read(sock, asio::buffer(headerbuf), use_awaitable);
            if (!nread) {
                Warning("{}: EOF\n", GetInfoStr());
                break;
            }
            if (nread != Hdr::HEADER_SIZE) throw ProtocolError("Short header read");
            Hdr hdr({});
            GenericVectorReader(SER_NETWORK, protoVersion, headerbuf, 0) >> hdr;
            if (!hdr.IsValid(params.netMagic)) throw ProtocolError("Bad header");
            if (hdr.IsOversized()) throw ProtocolError("Oversized message");
            CSerializedNetMsg msg;
            msg.m_type = hdr.GetCommand();
            msg.data.resize(hdr.nMessageSize);
            nread = co_await asio::async_read(sock, asio::buffer(msg.data), use_awaitable);
            if (nread != hdr.nMessageSize) throw ProtocolError("Short payload read");
            if (Span(Hash(msg.data)).first(hdr.CHECKSUM_SIZE) != Span(hdr.pchChecksum)) throw ProtocolError("Bad checksum");
            co_await MsgHandler(std::move(msg));
        }
    } catch (const std::exception &e) {
        Error("{}: Exception: {}\n", GetInfoStr(), e.what());
    }
}

void Connection::Misbehaving(int howmuch, std::string_view msg)
{
    misbehavior += howmuch;
    Warning("{}: {}: ({} -> {}) reason: {}\n", GetInfoStr(), __func__,  misbehavior - howmuch, misbehavior, msg);
    if (misbehavior >= MAX_MISBEHAVIOR) {
        scheduleDisconnect();
    }
}

async<> Connection::MsgHandler(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    Tic t0;
    const size_t msize = msg.data.size() + CMessageHeader::HEADER_SIZE;
    Log("{}: Got message: {}, size: {}\n", GetInfoStr(), msg.m_type, msize);
    // tally byte counts. Note: Normalize() should return a "peristent" string_view for this to not be UB!
    std::string_view const ncmd = NetMsgType::Normalize(msg.m_type);
    msg.m_type = ncmd; // writeback the normalized cmd to msg.m_type, so called-code doesn't have to worry
    msgByteCountsIn[ncmd] += msize;
    ++msgCountsIn[ncmd];
    bytesIn += msize;
    ++msgsIn;

    Defer d([&] {
        Log("{}: Handled '{}' in {} msec\n", GetInfoStr(), ncmd, t0.msecStr());
    });

    try {
        if (ncmd == NetMsgType::VERSION) {
            co_return co_await HandleVersion(std::move(msg));
        }

        if (!gotVersion) {
            // Must have a version message before anything else
            Misbehaving(10, "missing-version"sv);
            co_return;
        }

        if (ncmd == NetMsgType::PING) {
            co_return co_await HandlePing(std::move(msg));
        }

        if (ncmd == NetMsgType::PONG) {
            co_return co_await HandlePong(std::move(msg));
        }

        if (ncmd == NetMsgType::VERACK) {
            gotVerAck = true;
            co_return co_await DoOnceIfAfterHandshake();
        }

        if (ncmd == NetMsgType::INV || ncmd == NetMsgType::NOTFOUND) {
            co_return co_await HandleInvs(std::move(msg));
        }

        if (ncmd == NetMsgType::GETDATA) {
            co_return co_await HandleGetData(std::move(msg));
        }

        if (ncmd == NetMsgType::TX) {
            co_return co_await HandleTx(std::move(msg));
        }

        if (ncmd == NetMsgType::BLOCK) {
            co_return co_await HandleBlock(std::move(msg));
        }

        if (ncmd == NetMsgType::FEEFILTER) {
            co_return co_await HandleFeeFilter(std::move(msg));
        }

        if (ncmd == NetMsgType::ADDR || ncmd == NetMsgType::ADDRV2) {
            co_return co_await HandleAddr(std::move(msg));
        }

        if (ncmd == NetMsgType::HEADERS) {
            co_return co_await HandleHeaders(std::move(msg));
        }

        if (ncmd == NetMsgType::REJECT) {
            co_return co_await HandleReject(std::move(msg));
        }

    } catch (const std::ios_base::failure &e) {
        Warning("{}: Unserialize error processing message: '{}', exception was: {}", GetInfoStr(), ncmd, e.what());
        Misbehaving(1, "unserialize-error");
    }
}

async<> Connection::HandleVersion(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    if (gotVersion) {
        Misbehaving(1, "multiple-version"sv);
        co_await Send(NetMsgType::REJECT, NetMsgType::VERSION, REJECT_DUPLICATE, "Duplicate version message"sv);
        co_return;
    }
    gotVersion = true;

    VectorReader vRecv = MakeReader(msg);
    int64_t nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64_t nNonce = 0;
    uint64_t nServiceInt;
    int nVersion;
    int nSendVersion;
    this->relay = true;

    vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
    this->protoVersion = nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
    this->remote.nServices = ServiceFlags(nServiceInt);

    if (nVersion < MIN_PEER_PROTO_VERSION) {
        // disconnect from peers older than this proto version
        Warning("{}: peer using obsolete version {}; disconnecting\n", GetInfoStr(), nVersion);
        co_await Send(NetMsgType::REJECT,
                      NetMsgType::VERSION, REJECT_OBSOLETE, fmt::format("Version must be {} or greater", MIN_PEER_PROTO_VERSION));
        scheduleDisconnect();
        co_return;
    }

    if (!vRecv.empty()) {
        vRecv >> addrFrom >> nNonce;
    }
    if (!vRecv.empty()) {
        std::string strSubVer;
        vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
        this->cleanSubVer = SanitizeString(strSubVer);
        Log("{}: Got subversion: {}\n", GetInfoStr(), cleanSubVer);
    }
    if (!vRecv.empty()) {
        vRecv >> this->startingHeight;
    }
    if (!vRecv.empty()) {
        vRecv >> this->relay;
    }

    // Disconnect if we connected to self
    if (nNonce && inbound && nNonce == nLocalNonce) {
        Warning("{}: connected to self, disconnecting\n", GetInfoStr());
        scheduleDisconnect();
        co_return;
    }

    // only send version after we hear from them first, on inbound conns
    if (inbound) {
        co_await SendVersion();
    }

    co_await SendVerACK(/*nVersion*/);
    co_await DoOnceIfAfterHandshake();
}

async<> Connection::DoOnceIfAfterHandshake() {
    using namespace bitcoin;
    if (!didAfterHandshake && isFullyConnected()) {
        didAfterHandshake = true;
        if (auto const & [height, hash] = params.mostRecentCheckpoint; !hash.IsNull()) {
            // ask for a recent checkpoint
            Debug("{}: Requesting checkpoint header after height {}", GetInfoStr(), height);
            co_await Send(NetMsgType::GETHEADERS, CBlockLocator(std::vector<uint256>(1, hash)), uint256{});
        }
        co_await Send(NetMsgType::GETADDR);
        if (protoVersion >= SENDHEADERS_VERSION) {
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce blocks (such as pruning
            // nodes)
            co_await Send(NetMsgType::SENDHEADERS);
        }
        if (protoVersion >= SHORT_IDS_BLOCKS_VERSION) {
            bool const fAnnounceUsingCMPCTBLOCK = false;
            uint64_t const nCMPCTBLOCKVersion = 1;
            co_await Send(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion); // testing!
        }
        if (const auto invs2Spam = mgr->GetInvsToSpam(); invs2Spam.empty()) {
            if (!cleanSubVer.starts_with("/Satoshi:")) // Core nodes reject us if we send MEMPOOL without a bloom filter set
                co_await Send(NetMsgType::MEMPOOL); // testing!
            /* testing that Core disclosure bug...
            std::vector<CInv> invs;
            invs.reserve(MAX_INV_SZ); // 50,000
            FastRandomContext ctx;
            for (size_t i = 0; i < size_t(MAX_INV_SZ); ++i) {
                invs.emplace_back(GetDataMsg::MSG_BLOCK, ctx.rand256());
            }
            co_await Send(NetMsgType::INV, invs); // testing!
            */
        } else {
            // spam txns mode, enqueue all the invs from ConnMgr
            invQ.insert(invQ.end(), invs2Spam.begin(), invs2Spam.end());
        }
        scheduleInvSender();
        schedulePinger();
        scheduleCleaner();
    }
}

async<> Connection::HandlePing(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    if (protoVersion > BIP0031_VERSION) {
        uint64_t nonce = 0;
        MakeReader(msg) >> nonce;
        // Echo the message back with the nonce. This allows for two useful
        // features:
        //
        // 1) A remote node can quickly check if the connection is
        // operational.
        // 2) Remote nodes can measure the latency of the network thread. If
        // this node is overloaded it won't respond to pings quickly and the
        // remote node can avoid sending us more work, like chain download
        // requests.
        //
        // The nonce stops the remote getting confused between different
        // pings: without it, if the remote node sends a ping once per
        // second and this node takes 5 seconds to respond to each, the 5th
        // ping the remote sends would appear to return very quickly.
        co_await Send(NetMsgType::PONG, nonce);
    }
}

async<> Connection::HandlePong(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    std::string problem;
    bool reject = false;
    if (!lastPingNonceSent) {
        // spurious PONG!
        problem = "spurious-pong-msg";
        reject = true;
    } else {
        VectorReader vr = MakeReader(msg);
        uint64_t nonce;
        if (vr.size() >= sizeof(nonce)) {
            vr >> nonce;
            if (nonce == lastPingNonceSent) {
                lastPongTSMillis = GetTimeMillis();
                lastPingPongDelta = lastPongTSMillis - lastPingTSMillis; // TODO: reject negative or 0 values here?
                Debug("{}: Valid ping reply, measured latency: {} msec\n", GetInfoStr(), lastPingPongDelta);
            } else {
                problem = fmt::format("Ping reply nonce ({:x}) != what we expected ({:x})", nonce, lastPingNonceSent);
                Warning("{}: {}", GetInfoStr(), problem);
            }
            lastPingNonceSent = 0;
        } else {
            problem = "short-payload";
            reject = true;
        }
    }

    if (!problem.empty()) {
        Misbehaving(1, problem);
        if (reject) co_await Send(NetMsgType::REJECT, NetMsgType::PONG, REJECT_INVALID, problem);
    }
}

async<> Connection::HandleInvs(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    bool const notfound = msg.m_type == NetMsgType::NOTFOUND;
    std::vector<CInv> invs;
    MakeReader(msg) >> invs;
    Debug("{}: Got {} inv(s){}", GetInfoStr(), invs.size(), notfound ? " NOTFOUND" : "");
    if (invs.size() > MAX_INV_SZ) {
        Misbehaving(20, "oversized-inv");
        co_return co_await Send(NetMsgType::REJECT, NetMsgType::INV, REJECT_INVALID, "oversized-inv"sv);
    }
    // handle NOTFOUND
    if (notfound) {
        unsigned ct = 0;
        for (auto const & inv : invs) {
            if (inv.IsTx()) {
                ++ct;
                requestedInvs.erase(inv.hash);
            }
        }
        if (ct)
            Debug("{}: {} txns returned not found!", GetInfoStr(), ct);
        co_return;
    }

    // handle normal INV
    std::vector<CInv> wantInvs;
    wantInvs.reserve(invs.size());

    // first, register all invs seen as "peer has inv"
    for (const auto & inv : invs)
        peerHasInvs.insert(inv.hash);

    {
        LOCK_SHARED(mgr->mut);
        for (auto & inv : invs) {
            if (inv.IsTx() || inv.GetKind() == MSG_BLOCK) {
                if (!mgr->haveInv_nolock(inv.hash) && !requestedInvs.contains(inv.hash)) {
                    wantInvs.push_back(std::move(inv));
                    Debug("{}: Got new inv: {}", GetInfoStr(), wantInvs.back().ToString());
                } else {
                    Debug("{}: Ignoring inv: {}", GetInfoStr(), inv.ToString());
                }
            } else {
                Debug("{}: Ignoring unknown inv: {}", GetInfoStr(), inv.ToString());
            }
        }
    }
    invs = decltype(invs){}; // clear `invs` memory
    if ( ! wantInvs.empty()) {
        auto const now = GetTimeMicros();
        for (const auto & inv : wantInvs) {
            requestedInvs[inv.hash] = now;
        }
        Debug("{}: Requesting {} inv items ...", GetInfoStr(), wantInvs.size());
        co_await Send(NetMsgType::GETDATA, std::move(wantInvs));
    }
}

async<> Connection::HandleTx(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    CTransactionRef tx;
    MakeReader(msg) >> tx;

    double elapsedMSec;
    peerHasInvs.insert(tx->GetHashRef());
    if (auto it = requestedInvs.find(tx->GetHashRef()); it == requestedInvs.end()) {
        Misbehaving(1, fmt::format("Unrequested tx {}", tx->GetHashRef().ToString()));
        co_return;
    } else {
        elapsedMSec = (GetTimeMicros() - it->second) / 1e3;
        requestedInvs.erase(it);
    }
    if (auto [inserted, poolsz] = mgr->AddTxnToFakeMempool(GetNet(), tx); inserted)
        Debug("{}: Got TX reply in {:1.3f} msec. txid: {}, size: {}, version: {}, nins: {}, nouts: {}, poolsz: {}",
              GetInfoStr(), elapsedMSec, tx->GetHashRef().ToString(), tx->GetTotalSize(), tx->nVersion,
              tx->vin.size(), tx->vout.size(), poolsz);
    else
        Debug("{}: Got TX reply in {:1.3f} msec. txid: {}; already have tx",
              GetInfoStr(), elapsedMSec, tx->GetHashRef().ToString());
}

async<> Connection::HandleBlock(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    auto pblk = std::make_shared<CBlock>();
    CBlock & blk = *pblk;
    MakeReader(msg) >> blk;
    const auto hash = blk.GetHash();

    double elapsedMSec;
    peerHasInvs.insert(hash);
    if (auto it = requestedInvs.find(hash); it == requestedInvs.end()) {
        Misbehaving(1, fmt::format("Unrequested block {}", hash.ToString()));
        co_return;
    } else {
        elapsedMSec = (GetTimeMicros() - it->second) / 1e3;
        requestedInvs.erase(it);
    }
    if (mgr->ProcessBlock(GetNet(), hash, pblk)) {
        auto ins_n_outs = std::pair<size_t, size_t>(0U, 0U);
        ins_n_outs = std::accumulate(blk.vtx.begin(), blk.vtx.end(), ins_n_outs,
                                     [](const auto &accum, const auto &tx){
                                         return std::pair<size_t, size_t>(accum.first + tx->vin.size(),
                                                                          accum.second + tx->vout.size());
                                     });
        const auto tp = std::chrono::system_clock::from_time_t(blk.GetBlockTime());
        auto timeStr = fmt::format("{:%Y-%m-%d %H:%M:%S}", tp);
        Debug("{}: Got BLOCK reply in {:1.3f} msec. hash: {}, size: {}, time: {} ({}), prevBlk: {}, nTx: {}, nIns: {}, nOuts: {}",
              GetInfoStr(), elapsedMSec, hash.ToString(), bitcoin::GetSerializeSize(blk), blk.GetBlockTime(), timeStr,
              blk.hashPrevBlock.ToString(), blk.vtx.size(), ins_n_outs.first, ins_n_outs.second);
    } else
        Debug("{}: Got BLOCK reply in {:1.3f} msec. hash: {}; already seen block",
              GetInfoStr(), elapsedMSec, hash.ToString());
}

async<> Connection::HandleFeeFilter(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    Amount newFeeFilter;
    MakeReader(msg) >> newFeeFilter;
    if (MoneyRange(newFeeFilter)) {
        Log("{}: {}: {} -> {}", GetInfoStr(),
            styled(msg.m_type, fg(Color::bright_yellow)),
            CFeeRate(feeFilter).ToString(), CFeeRate(newFeeFilter).ToString());
        feeFilter = newFeeFilter;
    } else {
        auto const err = fmt::format("bad-fee-filter ({})", newFeeFilter.ToString());
        Misbehaving(1, err);
        co_await Send(NetMsgType::REJECT, msg.m_type, REJECT_INVALID, err);
    }
}

async<> Connection::HandleAddr(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    std::vector<CAddress> vAddr;
    const int flags = msg.m_type == NetMsgType::ADDRV2 ? ADDRV2_FORMAT : 0;
    MakeReader(msg, flags) >> vAddr;

    if (vAddr.size() > MAX_ADDR_TO_SEND) {
        auto err = "oversized-addr"sv;
        Misbehaving(20, "oversized-addr");
        co_return co_await Send(NetMsgType::REJECT, msg.m_type, REJECT_INVALID, err);
    }
    std::vector<const CAddress *> newAddrs;
    newAddrs.reserve(vAddr.size());
    {
        LOCK_SHARED(mgr->mut);
        for (auto const & addr : vAddr)
            if (!mgr->isAddrKnown_nolock(addr))
                newAddrs.push_back(&addr);
    }
    mgr->addAddrKnown({newAddrs.data(), newAddrs.size()});
    Log("{}: Got {}/{} new addresses", GetInfoStr(), newAddrs.size(), vAddr.size());
}

async<> Connection::HandleHeaders(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    auto vr = MakeReader(msg);
    std::vector<CBlockHeader> hdrs;
    vr >> hdrs;
    if (hdrs.size() > MAX_HEADERS_RESULTS) {
        auto err = fmt::format("Too many headers ({})", hdrs.size());
        Misbehaving(100, err);
        co_return co_await Send(NetMsgType::REJECT, msg.m_type, REJECT_INVALID, err);
    }
    Debug("{}: Got {} headers", GetInfoStr(), hdrs.size());
    if (!hdrs.empty() && !didVerifyCheckPoint && !GetCheckpointHash().IsNull() && startingHeight > -1 && GetCheckpointHeight() < unsigned(startingHeight)) {
        auto const & hdr = hdrs.front();
        if (hdr.hashPrevBlock == GetCheckpointHash()) {
            didVerifyCheckPoint = true;
            Log("{}: Checkpoint at height {} verified", GetInfoStr(), GetCheckpointHeight());
        } else {
            auto problem = fmt::format("Checkpoint at height {} mismatch (expected: {}, got: {})",
                                       GetCheckpointHeight(), GetCheckpointHash().ToString(), hdr.hashPrevBlock.ToString());
            Misbehaving(100, problem);
        }
    }
}

async<> Connection::HandleReject(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    std::string strMsg;
    uint8_t ccode;
    std::string strReason;
    auto vr = MakeReader(msg);
    vr >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode
       >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

    auto errmsg = fmt::format("{} code {}: {}", strMsg, ccode, strReason);
    if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX) {
        uint256 hash;
        vr >> hash;
        errmsg += fmt::format(": hash {}", hash.ToString());
    }
    Warning("{}: Reject {}", GetInfoStr(), SanitizeString(errmsg));
    co_return;
}

async<> Connection::HandleGetData(bitcoin::CSerializedNetMsg && msg)
{
    using namespace bitcoin;
    std::vector<CInv> invs, invsNotFound;
    MakeReader(msg) >> invs;
    if (invs.size() > MAX_INV_SZ) {
        auto err = fmt::format("Too many invs ({})", invs.size());
        Misbehaving(20, "too-many-inv");
        co_return co_await Send(NetMsgType::REJECT, msg.m_type, REJECT_INVALID, err);
    }

    Debug("{}: Received getdata ({} invsz)", GetInfoStr(), invs.size());

    if ( ! invs.empty()) {
        Debug("{}: First inv is a getdata for: {}", GetInfoStr(), invs.front().ToString());
    }

    for (auto & inv : invs) {
        const auto & hash = inv.hash;
        bool found = false;
        if (inv.IsTx()) {
            if (auto [tx, pctr, isSpam] = mgr->GetTxn(GetNet(), hash); tx) {
                found = true;
                if (Debug::enabled)
                    Debug("{}: Sending tx {}{} ({} bytes) ...", GetInfoStr(),
                          styled(tx->GetHashRef().ToString(), fg(Color::green)|fmt::emphasis::italic),
                          !isSpam ? std::string{} : fmt::format(" {}", styled("spam", fg(Color::white)|bg(Color::magenta))),
                          styled(tx->GetTotalSize(), fg(Color::bright_yellow)|fmt::emphasis::bold));
                co_await Send(NetMsgType::TX, *tx);
                if (pctr) pctr->fetch_add(1);
                peerHasInvs.insert(tx->GetHashRef());
            }
        } else {
            Debug("{}: Unsupported GETDATA for: {}", GetInfoStr(), inv.ToString());
        }
        if ( ! found)
            invsNotFound.push_back(std::move(inv));
    }

    if ( ! invsNotFound.empty()) {
        Debug("{}: Could not find {} invs\n", GetInfoStr(), styled(invsNotFound.size(), fg(Color::bright_black)|fmt::emphasis::italic));
        co_await Send(NetMsgType::NOTFOUND, std::move(invsNotFound));
    }

    co_return;
}

async<> Connection::Pinger()
{
    using namespace bitcoin;
    Debug("{}: Pinger started", GetInfoStr());
    Defer d([&]{ Debug("{}: Pinger stopped", GetInfoStr()); });

    while (!disconnectRequested) {
        if (isFullyConnected()) {
            if (lastPingTSMillis && /* test for neg. below 1 sec: */ lastPongTSMillis - lastPingTSMillis < -1'000'000) {
                Misbehaving(10, "No recent ping reply");
            }
            do { lastPingNonceSent = GetRand64(); } while (!lastPingNonceSent);
            lastPingTSMillis = GetTimeMillis();
            co_await Send(NetMsgType::PING, lastPingNonceSent);
        }
        // sleep 5 secs if not yet fully connected or 30 otherwise
        pinger.expires_from_now(std::chrono::seconds{isFullyConnected() ? pingIntervalSecs : 5});
        co_await pinger.async_wait(use_awaitable);
        Debug("{}: Pinger wakeup ..", GetInfoStr());
    }
}

async<> Connection::Cleaner()
{
    using namespace bitcoin;
    Debug("{}: Cleaner started", GetInfoStr());
    Defer d([&]{ Debug("{}: Cleaner stopped", GetInfoStr()); });

    while (!disconnectRequested) {
        if (isFullyConnected()) {
            // clean up expired "requestedInvs" messages
            auto const now = GetTimeMicros();
            std::vector<uint256> expired;
            for (auto const & [hash, time] : requestedInvs) {
                if (now - time > cleanIntervalSecs * 1'000'000)
                    expired.push_back(hash);
            }
            if ( ! expired.empty()) {
                Debug("{}: Deleting {}/{} expired in flight invs ...", GetInfoStr(), expired.size(), requestedInvs.size());
                for (auto const & hash : expired) requestedInvs.erase(hash);
            }
        }
        // sleep 5 secs if not yet fully connected or 30 otherwise
        cleaner.expires_from_now(std::chrono::seconds{isFullyConnected() ? cleanIntervalSecs : 5});
        co_await cleaner.async_wait(use_awaitable);
        Debug("{}: Cleaner wakeup ..", GetInfoStr());
    }
}

async<> Connection::InvSender()
{
    using namespace bitcoin;
    static constexpr bool verbose = false;
    Debug("{}: InvSender started", GetInfoStr());
    Defer d([&]{ Debug("{}: InvSender stopped", GetInfoStr()); });
    auto Wait = [&](int64_t msecs, bool ignoreCancelation = false) -> async<bool> {
        Tic t0;
        bool again;
        do {
            again = false;
            invSendTimer.expires_from_now(std::chrono::milliseconds{msecs});
            try {
                co_await invSendTimer.async_wait(use_awaitable);
            } catch (const asio::system_error &e) {
                if (e.code().value() == asio::error::basic_errors::operation_aborted) {
                    // canceled (maybe by a PushInv() call).
                    msecs -= t0.msec<int64_t>();
                    if (ignoreCancelation) {
                        // ignoring cancelation, keep waiting ...
                        if constexpr (verbose) Debug("{}: Ignoring cancelation, still have {} msecs left to wait ...", GetInfoStr(), msecs);
                        again = true;
                        continue;
                    }
                    if constexpr (verbose) Debug("{}: Responding to cancelation, still had {} msecs left", GetInfoStr(), msecs);
                    co_return false;
                }
                // other error, bubble it out
                throw;
            }
        } while(again && msecs > 0);
        co_return true;
    };
    while (!isFullyConnected()) {
        co_await Wait(100);
        if (disconnectRequested) co_return;
    }

    constexpr size_t maxInvSend = std::min<size_t>(MAX_INV_SZ, 100u /* default max orphans */);

    std::vector<CInv> invs;

    // Keep polling for new invs to send
    while (isFullyConnected() && !disconnectRequested) {
        if (!invQ.empty()) {
            const auto endit = invQ.begin() + std::min(maxInvSend, invQ.size());
            invs.insert(invs.end(), invQ.begin(), endit);
            invQ.erase(invQ.begin(), endit);
            const auto sent = invs.size();
            if constexpr (verbose) Debug("{}: {} sending {} invs ...", GetInfoStr(), __func__, invs.size());
            co_await Send(bitcoin::NetMsgType::INV, std::move(invs));
            invs.clear();
            co_await Wait(1 * sent, true); // TODO: tune this!
        } else {
            Tic t0;
            const bool expired [[maybe_unused]] =
                /* wake up every 1 min, but may be "cancelled" to wakeup early if PushInv() is called */
                co_await Wait(60LL * 1000LL);
            if constexpr (verbose)
                Debug("{}: {} woke up after {} msec, timer {}", GetInfoStr(), __func__, t0.msecStr(), expired ? "expired." : "woke up early!");
        }
    }
}

UniValue::Object Connection::GetStats() const
{
    UniValue::Object ret;
    ret.reserve(21);
    ret.emplace_back("id", GetId());
    ret.emplace_back("connected", sock.is_open());
    ret.emplace_back("fully connected", isFullyConnected());
    ret.emplace_back("net", params.name);
    ret.emplace_back("local", local.ToString());
    ret.emplace_back("remote", remote.ToString());
    if (lastPingPongDelta != 0) ret.emplace_back("ping_msec", lastPingPongDelta);
    ret.emplace_back("subver", cleanSubVer);
    ret.emplace_back("version", protoVersion);
    ret.emplace_back("serviceFlags", fmt::format("{:#011b}", uint64_t(remote.nServices)));
    ret.emplace_back("relay", relay);
    ret.emplace_back("misbehavior", fmt::format("{}/{}", misbehavior, MAX_MISBEHAVIOR));
    ret.emplace_back("startingHeight", startingHeight);
    ret.emplace_back("checkpointVerified", didVerifyCheckPoint);
    ret.emplace_back("elapsed (secs)", tstart.secsStr());
    ret.emplace_back("bytesIn", bytesIn);
    ret.emplace_back("bytesOut", bytesOut);
    ret.emplace_back("msgsIn", msgsIn);
    ret.emplace_back("msgsOut", msgsOut);
    struct Cts {
        size_t ctIn{}, ctOut{}, bytesIn{}, bytesOut{};
    };
    using Ctr = std::map<std::string_view, Cts>;
    Ctr ctr;
    for (auto const & [msg, val]: msgByteCountsIn) ctr[msg].bytesIn += val;
    for (auto const & [msg, val]: msgByteCountsOut) ctr[msg].bytesOut += val;
    for (auto const & [msg, val]: msgCountsIn) ctr[msg].ctIn += val;
    for (auto const & [msg, val]: msgCountsOut) ctr[msg].ctOut += val;

    UniValue::Object uvmsgctr;
    uvmsgctr.reserve(ctr.size());
    for (auto const & [msg, cts] : ctr) {
        UniValue::Object subobj;
        subobj.reserve(4);
        subobj.emplace_back("bytesIn", cts.bytesIn);
        subobj.emplace_back("bytesOut", cts.bytesOut);
        subobj.emplace_back("msgsIn", cts.ctIn);
        subobj.emplace_back("msgsOut", cts.ctOut);
        uvmsgctr.emplace_back(msg, std::move(subobj));
    }

    ret.emplace_back("message stats", std::move(uvmsgctr));

    UniValue::Object uvinvs;
    uvinvs.reserve(requestedInvs.size());
    auto const now = bitcoin::GetTimeMicros();
    for (auto const & [hash, time]: requestedInvs) {
        uvinvs.emplace_back(hash.ToString(), (now - time) / 1e6);
    }

    ret.emplace_back("invs in flight", std::move(uvinvs));

    return ret;
}

UniValue::Object ConnMgr::GetStats() const
{
    UniValue::Object ret;
    ret.reserve(6);
    LOCK_SHARED(mut);
    ret.emplace_back("fake_mempool_txns", fakeMempool.size());
    ret.emplace_back("num_conns", conns.size());
    ret.emplace_back("num_lost_conns", connsLost);
    ret.emplace_back("num_connected_inbound", nInbound.load());
    ret.emplace_back("num_connected_outbound", nOutbound.load());
    ret.emplace_back("num_bound_listen_ports", nServers.load());
    UniValue::Object uvconns;
    uvconns.reserve(conns.size());
    for (auto const &wc : conns | std::views::values) {
        if (auto c = wc.lock())
            uvconns.emplace_back(c->GetName(), c->GetStats());
    }
    ret.emplace_back("connections", std::move(uvconns));
    return ret;
}

async<> Client(ConnMgr &mgr, Net net, std::string_view hostname, uint16_t port) {
    for (;;) {
        auto executor = co_await this_coro::executor;
        std::string excMsg;
        try {
            tcp::socket sock(executor);
            tcp::resolver rslv(executor);
            Log("Connecting to {}:{} ...", hostname, port);
            auto results = co_await rslv.async_resolve(hostname, fmt::format("{}", port), use_awaitable);
            if (results.empty()) throw std::runtime_error("Unable to resolve, no results");
            co_await asio::async_connect(sock, results, use_awaitable);
            if (!sock.is_open()) throw std::runtime_error("Socket not open");
            auto conn = mgr.CreateConnection(std::move(sock), false, net, std::string{hostname});
            co_await conn->ProcessLoop();
        } catch (const std::exception &e) {
            excMsg = e.what();
        }
        if (!excMsg.empty())
            Warning("{}:{}: Error: '{}' -- Will try again in 5 minutes ...", hostname, port, excMsg);
        else
            Warning("{}:{}: Connection lost, will try again in 5 minutes ...", hostname, port);
        asio::steady_timer timer(executor);
        timer.expires_from_now(std::chrono::minutes{5});
        co_await timer.async_wait(use_awaitable);
    }
}

async<> Server(ConnMgr &mgr, Net net, std::string_view iface, uint16_t port) {
    asio::ip::address addr;
    std::error_code ec;
    addr = asio::ip::make_address_v4(iface, ec);
    if (ec) addr = asio::ip::make_address_v6(iface, ec);
    if (ec) throw std::invalid_argument(fmt::format("Bad interface string: {}", iface));
    auto executor = co_await this_coro::executor;
    tcp::acceptor acceptor(executor, {addr, port});
    const std::string hostPort = fmt::format("{}:{}", iface, port);
    Log("Listening on {} ({}) ...", hostPort, Net2Name(net));
    ++mgr.nServers;
    Defer d([&]{ --mgr.nServers; });
    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        if (socket.is_open()) {
            auto ep = socket.remote_endpoint();
            Log("Inbound connection from {}:{} (interface: {}) ...", ep.address().to_string(), ep.port(), hostPort);
            executor = co_await this_coro::executor;
            auto conn = mgr.CreateConnection(std::move(socket), true, net);
            co_spawn_shared(*conn, executor, conn->ProcessLoop(), detached);
        }
    }
}

void printStats(const ConnMgr &mgr)
{
    Log("\n--- Stats:\n{}\n", styled(UniValue::stringify(mgr.GetStats(), 2), fg(Color::green)|bg(Color::black)|fmt::emphasis::bold));
}

struct ParsedArgs
{
    using Tup = std::tuple<Net, std::string, uint16_t>;
    using VecTup = std::vector<Tup>;

    VecTup connectToHosts;
    VecTup serverBinds;
    std::optional<std::string> httpServerInterface;
    std::optional<uint16_t> httpServerPort;
    std::vector<CTransactionRef> txnsToSpam;

    static Tup ParseHostPortNet(std::string_view s) { return ParseHostPortNetCommon(s, true); }
    static auto ParseHostPort(std::string_view s) {
        std::pair<std::string, uint16_t> ret;
        std::tie(std::ignore, ret.first, ret.second) = ParseHostPortNetCommon(s, false);
        return ret;
    }

    static uint16_t ParsePort(std::string_view s, std::optional<std::string_view> orig_arg = {});

private:
    static Tup ParseHostPortNetCommon(std::string_view arg, bool acceptNetPart);
};

/* static */
uint16_t ParsedArgs::ParsePort(std::string_view s, std::optional<std::string_view> orig_arg)
{
    uint16_t port;
    std::from_chars_result res{};
    constexpr const auto ok = std::errc{};
    if (auto *beg = &*s.begin(), *end = &*s.end();
        beg == end || (res = std::from_chars(beg, end, port)).ptr != end || res.ec != ok) {
        throw std::runtime_error(fmt::format("Bad port ({}) for argument: {}",
                                             std::make_error_code(res.ec == ok ? std::errc::invalid_argument : res.ec)
                                                 .message(),
                                             orig_arg.value_or(s)));
    }
    return port;
}

/* static */
auto ParsedArgs::ParseHostPortNetCommon(std::string_view const orig_arg, bool const acceptNetPart) -> Tup
{
    std::string arg{orig_arg};
    std::string host;
    auto ThrowIfEmptyHost = [&orig_arg, &host] {
        if (host.empty()) throw std::runtime_error(fmt::format("Empty host in arg: {}", orig_arg));
    };
    size_t min_parts = 2, max_parts = 2 + acceptNetPart;
    // first match ipv6 if any, because it contains colons and that can mess us up
    if (size_t pos; !arg.empty() && arg[0] == '[' && (pos = arg.find_last_of(']')) != arg.npos) {
        host = arg.substr(1, pos - 1);
        ThrowIfEmptyHost();
        --min_parts, --max_parts;
        arg.erase(0, pos + 2);
    }
    std::deque<std::string> parts;
    boost::algorithm::split(parts, arg, boost::is_any_of(":"));
    if (parts.size() < min_parts || parts.size() > max_parts) {
        throw std::runtime_error(fmt::format("Bad argument: {}", orig_arg));
    }
    // accept host
    if (host.empty()) {
        host = std::move(parts.front());
        ThrowIfEmptyHost();
        parts.pop_front();
    }
    // parse port (may throw)
    uint16_t const port = ParsePort(parts.front(), orig_arg);
    // accept port
    parts.pop_front();

    // parse optional Net part at end
    Net net = Net::Main;
    if (!parts.empty()) {
        // parse last net arg
        auto res = Name2Net(parts.front());
        if (!res || *res == Net::AnyNet) throw std::runtime_error(fmt::format("Bad net for argument: {}", orig_arg));
        net = *res;
        parts.pop_front();
    }
    Debug("Parsed '{}' -> {}host: {}, port: {}", orig_arg, acceptNetPart ? fmt::format("net: {}, ", Net2Name(net)) : "",
          host, port);
    return {net, host, port};
}

ParsedArgs parseArgs(int argc, const char **argv)
{
    using Tup = ParsedArgs::Tup;

    std::array const defaultConnect = {
        Tup{Main, "localhost", 8888}, // this should error
        Tup{Main, "thisshouldfail.google.com", 8888}, // this should error
        Tup{Main, "c3.c3-soft.com", 8333},
        Tup{Chip, "c3.c3-soft.com", 48333},
        Tup{Main, "bch.loping.net", 8333},
        Tup{Main, "tbch.loping.net", 18333}, // this is wrong -- testing error case
        Tup{Scale, "sbch.loping.net", 38333},
        Tup{Reg, "localhost", 9333}, // our regtest node.. should normally fail but maybe is up sometimes
    };

    ParsedArgs ret;
    using namespace argparse;
    ArgumentParser ap(argv[0], VERSION_STR);

    ap.add_argument("connect")
        .help("Peer spec to connect to").metavar("HOST:PORT[:NET]")
        .nargs(nargs_pattern::any)
        .append();

    ap.add_argument("--listen")
        .help("Bind to this interface and port to listen for connections").metavar("INTERFACE:PORT[:NET]")
        .nargs(nargs_pattern::any)
        .append();

    ap.add_argument("--http", "-H")
        .help("Start the info http server on this interface and port (0 to disable)").metavar("[INTERFACE:]PORT")
        .default_value("127.0.0.1:8080");

    ap.add_argument("--spamtxs", "-S")
        .help("Spam txs when connecting to peers from this JSON file (JSON content should be an array of hex encoded txns)").metavar("JSONFILE")
        .nargs(1);

    using namespace boost;
    std::string const netlist = algorithm::join(
        netChainParams | adaptors::transformed([](const auto &cp) { return boost::algorithm::to_lower_copy(std::string{cp.name}); }),
        ", "
    );

    ap.add_epilog("Notes:\n"
                  " - All IPv6 addresses whould be in brackets, e.g. [::1]\n"
                  " - HOST above may be a hostname or an IP address\n"
                  " - INTERFACE above must be a valid local interface IP address\n"
                  " - NET above is one of: " + netlist);

    try {
        ap.parse_args(argc, argv);

        if (ap.is_used("connect")) {
            for (const auto &arg : ap.get<std::vector<std::string>>("connect")) {
                ret.connectToHosts.push_back(ParsedArgs::ParseHostPortNet(arg));
            }
        }
        if (ap.is_used("listen")) {
            for (const auto &arg : ap.get<std::vector<std::string>>("listen")) {
                ret.serverBinds.push_back(ParsedArgs::ParseHostPortNet(arg));
            }
        }
        if (ap.is_used("spamtxs")) {
            const auto &file = ap.get<>("spamtxs");
            FILE *f = std::fopen(file.c_str(), "rt");
            if (!f) throw std::runtime_error(fmt::format("Unable to open '{}': {}", file, std::strerror(errno)));
            Defer d([&]{ if (f) std::fclose(f), f = nullptr; });
            char buf[4096];
            std::string json;
            while (const size_t nread = std::fread(buf, 1, sizeof(buf), f)) {
                json.append(buf, std::min(nread, sizeof(buf)));
            }
            UniValue uv;
            std::string::size_type err{};
            if ( ! uv.read(json, &err)) {
                throw std::runtime_error(fmt::format("Failed to read json from '{}', error at position {}", file, err));
            }
            if (! uv.isArray()) throw std::runtime_error("Expected JSON top-level object to be an array");
            for (const auto &item : uv.get_array()) {
                const auto txbytes = bitcoin::ParseHex(item.get_str());
                CTransactionRef & tx = ret.txnsToSpam.emplace_back();
                bitcoin::VectorReader(bitcoin::SER_NETWORK, bitcoin::PROTOCOL_VERSION, txbytes, 0, tx);
                if (!tx) throw std::runtime_error("Unexpected null ptr for unserialized tx! This shouldn't happen!");
            }
        }

        // --http / -H
        auto const pstr = ap.get("http");
        if (pstr.find(':') != pstr.npos) {
            std::tie(ret.httpServerInterface, ret.httpServerPort) = ParsedArgs::ParseHostPort(pstr);
        } else if (uint16_t const p = ParsedArgs::ParsePort(pstr)) {
            ret.httpServerPort = p;
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        std::exit(EXIT_FAILURE);
    }

    if (ret.connectToHosts.empty() && ret.serverBinds.empty())
        ret.connectToHosts = {defaultConnect.begin(), defaultConnect.end()};

    return ret;
}

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
std::unique_ptr<HttpServer> StartHttpServer(ConnMgr &mgr, const std::string_view address, const uint16_t port)
{
    auto httpSrv = std::make_unique<HttpServer>();
    httpSrv->config.address = address;
    httpSrv->config.port = port;
    httpSrv->config.max_request_streambuf_size = 1<<16; // 64 KiB; change this if we expect larger requests
    httpSrv->io_service = mgr.io_context;
    httpSrv->resource["/.*"]["GET"] = [&mgr](auto response, auto request) {
        Debug(Color::bright_blue, "HTTP: {} request \"{}\"", request->method, request->path);
        constexpr bool debug_incoming_headers = false;
        if constexpr (debug_incoming_headers) {
            for (const auto & [key, value] : request->header) {
                Debug(Color::bright_black, "{}: {}", key, value);
            }
        }
        // /, /stats
        if (request->path == "/stats") {
            const auto html = html_bits::MakePrettyHtmlForJson("BCH P2P Program Stats", mgr.GetStats());
            response->write(html, {{"Content-type", "text/html"}});
        } else if (request->path == "/") {
            // redirect "/" to "/stats"
            response->write(SimpleWeb::StatusCode::redirection_moved_permanently, {{"Location", "/stats"}});
        } else {
            // everything else is not found
            response->write(SimpleWeb::StatusCode::client_error_not_found);
            Debug(Color::bright_black, "HTTP: not found for \"{}\"", request->path);
        }
    };
    httpSrv->on_error = [](auto req, auto err) {
        auto const ep = req->remote_endpoint();
        auto const hostport = ep == decltype(ep){} ? "<lost_conn>" : fmt::format("{}:{}", ep.address().to_string(), ep.port());
        Debug(Color::bright_black, "Error from {}: {}", hostport, err.message());
    };
    try {
        httpSrv->start([](auto port){ Log("HTTP service started ok, port {}", port); });
    } catch (const std::exception &e) {
        auto msg = fmt::format("Failed to start HTTP server on {}{}{} ({})",
                               address.empty() ? "port " : address, address.empty() ? "" : ":",
                               port, e.what());
        throw std::runtime_error(msg);
    }
    return httpSrv;
}

} // namespace

int main(int argc, const char *argv[]) {
    bitcoin::util::ThreadSetInternalName("M");
    Debug::enabled = true;
    bitcoin::LogInstance().m_log_timestamps = bitcoin::LogInstance().m_log_time_micros = true;
    bitcoin::LogInstance().m_log_threadnames = true;
    std::signal(SIGPIPE, SIG_IGN); // required to avoid SIGPIPE when write()/read()

    ParsedArgs args = parseArgs(argc, argv); // may exit prematurely if --help, --version, or bad args;
    auto & [connectToHosts, serverBinds, httpInterface, httpPort, txnsToSpam] = args;

    bitcoin::RandomInit();
    if (!bitcoin::Random_SanityCheck()) fmt::print(stderr, "{}", styled("WARNING: Random_SanityCheck failed!", fg(fmt::terminal_color::bright_yellow) | fmt::emphasis::bold));
    Log("Using SHA256: {}", styled(bitcoin::SHA256AutoDetect(), fg(fmt::terminal_color::white)|bg(fmt::terminal_color::blue)|fmt::emphasis::bold));

    try {
        ConnMgr mgr(std::move(txnsToSpam));
        asio::io_context & io_context = *mgr.io_context;

        asio::signal_set signals(io_context, SIGINT, SIGTERM, SIGUSR1);
        signals.add(SIGQUIT);
        std::function<void()> registerSigs;
        registerSigs = [&] {
            signals.async_wait([&](std::error_code ec, int sig){
                if (!ec) {
                    if (sig == SIGUSR1 || sig == SIGQUIT) {
                        printStats(mgr);
                        // upon receiving the sig, we must re-register
                        registerSigs();
                        return;
                    }
                    fmt::print(fg(Color::green)|fmt::emphasis::italic, "\n--- Caught signal {}, exiting ...\n", styled(sig, fg(Color::bright_white)|bg(Color::blue)));
                    io_context.stop();
                } else {
                    Error("\n--- Sighandler error: {}", styled(ec.message(), fg(Color::bright_white)|bg(Color::blue)));
                }
            });
        };
        registerSigs();

        size_t errct = 0;

        auto handler = [&](std::string_view host, uint16_t port, std::exception_ptr exc, bool is_server=false) {
            if (exc) {
                try {
                    std::rethrow_exception(exc);
                } catch (const std::exception &e) {
                    if (is_server || ++errct == connectToHosts.size())
                        throw;
                    Warning("{}:{}: Exception: {}", host, port, e.what());
                }
            }
        };

        for (const auto & [net, host, port] : connectToHosts) {
            co_spawn(io_context, Client(mgr, net, host, port),
                     [&handler, host, port](auto exc) { handler(host, port, exc); });
        }

        for (const auto & [net, host, port] : serverBinds) {
            co_spawn(io_context, Server(mgr, net, host, port),
                     [&handler, host, port](auto exc) { handler(host, port, exc, true); });
        }

        // Handle HTTP on whatever host & port the user specified, or default to port 8080
        std::unique_ptr<HttpServer> httpSrv;
        if (httpPort.has_value()) {
            httpSrv = StartHttpServer(mgr, httpInterface.value_or(std::string{} /* any */), *httpPort);
        } else {
            Debug("HTTP service disabled");
        }

        io_context.run();
    } catch (std::exception& e) {
        Error("Exception: {}", styled(e.what(), fmt::emphasis::bold|bg(Color::bright_red)|fg(Color::bright_white)));
    }

    return EXIT_SUCCESS;
}
