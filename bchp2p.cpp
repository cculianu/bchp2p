#include "bitcoin/hash.h"
#include "bitcoin/logging.h"
#include "bitcoin/protocol.h"
#include "bitcoin/streams.h"
#include "bitcoin/random.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin/utiltime.h"

#include "util.h"

#include <asio.hpp>

#include <fmt/format.h>

#include <bit>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

using asio::ip::tcp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
namespace this_coro = asio::this_coro;

template <typename T = void, typename E = asio::any_io_executor>
using async = awaitable<T, E>; // make it look a little more like Python? ;)

using namespace std::string_view_literals;

struct ProtocolError : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class Connection;

struct ChainParams
{
    std::string_view name;
    bitcoin::CMessageHeader::MessageMagic netMagic;
    std::pair<uint32_t, bitcoin::uint256> mostRecentCheckpoint;
};

enum Net : uint8_t { Main = 0, Chip, Test3, Test4, Scale, NumNets };

static const std::array<ChainParams, NumNets> netChainParams = {
    ChainParams{ .name = "Main", .netMagic = {0xe3, 0xe1, 0xf3, 0xe8},
                .mostRecentCheckpoint = {823112, bitcoin::uint256S("0000000000000000014e75464739e2b6f12a756f0d749cc15c243adb73ffbd5b")}},
    ChainParams{ .name = "Chip", .netMagic = {0xe2, 0xb7, 0xda, 0xaf},
                .mostRecentCheckpoint = {178140, bitcoin::uint256S("000000003c37cc0372a5b9ccacca921786bbfc699722fc41e9fdbb1de4146ef1")}},
    ChainParams{ .name = "Test3", .netMagic = {0xf4, 0xe5, 0xf4, 0xf4},
                .mostRecentCheckpoint = {1582896, bitcoin::uint256S("000000000000088ef4d908ed35dc511b97fe4df78d5e37ab1e1aea4084d19506")}},
    ChainParams{ .name = "Test4", .netMagic = {0xe2, 0xb7, 0xda, 0xaf},
                .mostRecentCheckpoint = {178150, bitcoin::uint256S("00000000bd585ef9f37712bca4539acd8ec7c3b02620186dda1ee880bc07ba71")}},
    ChainParams{ .name = "Scale", .netMagic = {0xc3, 0xaf, 0xe1, 0xa2},
                .mostRecentCheckpoint = {10000, bitcoin::uint256S("00000000b711dc753130e5083888d106f99b920b1b8a492eb5ac41d40e482905")}},
};

//static_assert

struct ConnMgr
{
    std::set<Connection *> conns;
    asio::io_context io_context{1};

    void add(Connection *c) { conns.insert(c); }
    void rm(Connection *c) {
        conns.erase(c);
        if (conns.empty()) {
            io_context.stop();
        }
    }
};

class Connection
{
    ConnMgr * const mgr;
    tcp::socket sock;
    bitcoin::CAddress local, remote;
    const bool inbound;
    const Net net;
    const ChainParams &params;
    const std::string infoName;
    const uint64_t nLocalNonce;
    bitcoin::Tic tstart;
    bool disconnectRequested = false, pingerScheduled = false;

    std::map<std::string_view, size_t> msgByteCountsIn, msgByteCountsOut, msgCountsIn{}, msgCountsOut{};
    size_t bytesIn{}, bytesOut{}, msgsIn{}, msgsOut{};

    int protoVersion = bitcoin::INIT_PROTO_VERSION;
    std::string cleanSubVer;
    bool sentVersion = false, sentVerAck = false, gotVersion = false, gotVerAck = false, didAfterHandshake = false;
    bool relay = false;
    int misbehavior = 0;
    static constexpr int MAX_MISBEHAVIOR = 100;

    [[nodiscard]]
    async<> MsgHandler(bitcoin::CSerializedNetMsg msg);

    [[nodiscard]] async<> SendVersion();
    [[nodiscard]] async<> SendVerACK(int nVersion = 0);
    [[nodiscard]] async<> Send(bitcoin::CSerializedNetMsg msg);
    template <typename ...Args>
    [[nodiscard]] async<> Send(std::string_view msg_type, Args ...args) {
        using namespace bitcoin;
        co_await Send(CNetMsgMaker(protoVersion).Make(msg_type, std::forward<Args>(args)...));
    }

    [[nodiscard]] async<> HandleVersion(bitcoin::CSerializedNetMsg msg);
    [[nodiscard]] async<> HandlePing(bitcoin::CSerializedNetMsg msg);
    [[nodiscard]] async<> HandlePong(bitcoin::CSerializedNetMsg msg);

    [[nodiscard]] async<> DoOnceIfAfterHandshake(); // does GETADDR, etc -- stuff we do immediately after a state change to "fully established"

    static constexpr int pingIntervalSecs = 30;
    uint64_t lastPingNonceSent = 0;
    int64_t lastPingTSMillis = 0, lastPongTSMillis = 0, lastPingPongDelta = 0;
    [[nodiscard]] async<> Pinger(); // periodically pings node every 60 seconds

    std::string GetInfoStr() const {
        const int64_t nTimeMicros = bitcoin::GetTimeMicros();
        std::string dtstr = bitcoin::FormatISO8601DateTime(nTimeMicros / 1'000'000);
        if (dtstr.back() == 'Z') dtstr.pop_back();
        dtstr += fmt::format(".{:06d}Z", nTimeMicros % 1'000'000);
        // this is a hack
        return fmt::format("{} {} ({})", dtstr,
                           infoName.empty() ? remote.ToStringIPPort() : fmt::format("{}:{}", infoName, remote.ToStringPort()),
                           params.name);
    }

    void Misbehaving(int score, std::string_view msg);

    asio::steady_timer pinger;

public:
    Connection(ConnMgr *mgr, tcp::socket &&s_, bool inbound_, const Net net_, std::string infoName_ = {})
        : mgr(mgr), sock(std::move(s_)), inbound(inbound_), net(net_), params(netChainParams.at(net)), infoName(std::move(infoName_)),
          nLocalNonce(bitcoin::GetRand64()), pinger(sock.get_executor())
    {
        mgr->add(this);
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
    }

    Connection(Connection &&) = delete;

    ~Connection() { mgr->rm(this); }

    [[nodiscard]]
    async<> ProcessLoop();

    [[nodiscard]]
    async<> CancelProcessing() {
        Debug("{}: Canceling processing ...\n", GetInfoStr());
        disconnectRequested = true;
        Debug("{}: shutdown ...\n", GetInfoStr());
        asio::error_code ec;
        sock.cancel(ec);
        sock.shutdown(sock.shutdown_both);
        pinger.cancel(ec);
        auto e = co_await this_coro::executor;
        asio::steady_timer t(e);
        t.expires_from_now(std::chrono::milliseconds{10});
        co_await t.async_wait(use_awaitable);
        Debug("{}: close ...\n", GetInfoStr());
        sock.close();
    }

    void scheduleDisconnect() {
        if (!disconnectRequested) {
            disconnectRequested = true;
            co_spawn(sock.get_executor(), CancelProcessing(), detached);
        }
    }

    void schedulePinger() {
        if (!pingerScheduled) {
            pingerScheduled = true;
            co_spawn(sock.get_executor(), Pinger(), detached);
        }
    }

    bool isFullyConnected() const { return sentVersion && sentVerAck && gotVersion && gotVerAck; }
};

async<> Connection::SendVersion()
{
    using namespace bitcoin;
    const int64_t nTime = static_cast<int64_t>(GetTime());
    const int64_t nLocalServices = local.nServices;
    const int nBestHeight = 0; // GetRequireHeight();
    const std::string ver = "/TestP2P:0.0.1/";
    const uint8_t fRelayTxs = 1;
    const CAddress addrMe = CAddress(CService(), ServiceFlags(nLocalServices));
    sentVersion = true;

    co_await Send(NetMsgType::VERSION, // cmd
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
    std::vector<uint8_t> hdrdata;
    VectorWriter(SER_NETWORK, PROTOCOL_VERSION, hdrdata, 0) << hdr;
    const size_t msgSize = hdrdata.size() + msg.data.size();
    const auto cmd = hdr.GetCommand();
    Log("{}: Sending msg {} {} bytes\n", GetInfoStr(), cmd, msgSize);
    const auto ncmd = NetMsgType::Normalize(cmd); // assumption: Normalize() returns a long-lived string_view!
    msgByteCountsOut[ncmd] += msgSize;
    ++msgCountsOut[ncmd];
    bytesOut += msgSize;
    ++msgsOut;
    Tic t0;
    co_await asio::async_write(sock, asio::buffer(hdrdata), use_awaitable); // send header
    co_await asio::async_write(sock, asio::buffer(msg.data), use_awaitable); // send payload
    Debug("{}: {} msec for '{}' xfer\n", GetInfoStr(), t0.msecStr(), ncmd);
}

async<> Connection::ProcessLoop()
{
    tstart = bitcoin::Tic();
    Log("{}: Connected\n", GetInfoStr());
    Defer d([&] { Log("{}: ProcessLoop ended, {} secs elapsed\n", GetInfoStr(), tstart.secsStr(3)); });
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

async<> Connection::MsgHandler(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    Tic t0;
    const size_t msize = msg.data.size() + CMessageHeader::HEADER_SIZE;
    Log("{}: Got message: {}, size: {}\n", GetInfoStr(), msg.m_type, msize);
    // tally byte counts. Note: Normalize() should return a "peristent" string_view for this to not be UB!
    std::string_view const ncmd = NetMsgType::Normalize(msg.m_type);
    msgByteCountsIn[ncmd] += msize;
    ++msgCountsIn[ncmd];
    bytesIn += msize;
    ++msgsIn;

    Defer d([&] {
        Log("{}: Handled '{}' in {} msec\n", GetInfoStr(), ncmd, t0.msecStr());
    });

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
}

async<> Connection::HandleVersion(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    if (gotVersion) {
        Misbehaving(1, "multiple-version"sv);
        co_await Send(NetMsgType::REJECT, NetMsgType::VERSION, REJECT_DUPLICATE, "Duplicate version message"sv);
        co_return;
    }
    gotVersion = true;

    VectorReader vRecv(SER_NETWORK, protoVersion, msg.data, 0);
    int64_t nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64_t nNonce = 0;
    uint64_t nServiceInt;
    int nVersion;
    int nSendVersion;
    int nStartingHeight = -1;
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
        vRecv >> nStartingHeight;
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
        co_await Send(NetMsgType::MEMPOOL); // testing!
        schedulePinger();
    }
}

async<> Connection::HandlePing(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    if (protoVersion > BIP0031_VERSION) {
        uint64_t nonce = 0;
        VectorReader(SER_NETWORK, protoVersion, msg.data, 0) >> nonce;
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

async<> Connection::HandlePong(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    std::string problem;
    bool reject = false;
    if (!lastPingNonceSent) {
        // spurious PONG!
        problem = "spurious-pong-msg";
        reject = true;
    } else {
        VectorReader vr(SER_NETWORK, protoVersion, msg.data, 0);
        uint64_t nonce;
        if (vr.size() >= sizeof(nonce)) {
            vr >> nonce;
            if (nonce == lastPingNonceSent) {
                lastPongTSMillis = GetTimeMillis();
                lastPingPongDelta = lastPongTSMillis - lastPingTSMillis; // TODO: reject negative or 0 values here?
                Debug("{}: Valid ping reply, measured latency: {:1.3f} msec\n", GetInfoStr(), lastPingPongDelta / 1e3);
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

async<> Connection::Pinger()
{
    using namespace bitcoin;
    Debug("{}: Pinger started", GetInfoStr());
    Defer d([&]{ Debug("{}: Pinger stopped", GetInfoStr()); });

    while (!disconnectRequested) {
        if (!disconnectRequested && isFullyConnected()) {
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

async<> client(ConnMgr *mgr, Net net, std::string_view hostname, uint16_t port) {
    auto portstr = fmt::format("{}", port);
    auto executor = co_await this_coro::executor;
    tcp::socket sock(executor);
    tcp::resolver rslv(executor);
    auto results = co_await rslv.async_resolve(hostname, portstr, use_awaitable);
    if (results.empty()) throw std::runtime_error(fmt::format("Unable to resolve {}:{}", hostname, port));
    co_await asio::async_connect(sock, results, use_awaitable);
    if (!sock.is_open()) throw std::runtime_error(fmt::format("Socket not open for {}:{}", hostname, port));
    Connection conn(mgr, std::move(sock), false, net, std::string{hostname});
    co_await conn.ProcessLoop();
}

int main() {
    Debug::enabled = true;
    bitcoin::LogInstance().m_log_timestamps = bitcoin::LogInstance().m_log_time_micros = true;
    std::signal(SIGPIPE, SIG_IGN); // required to avoid SIGPIPE when write()/read()

    bitcoin::RandomInit();
    if (!bitcoin::Random_SanityCheck()) fmt::print(stderr, "{}", styled("WARNING: Random_SanityCheck failed!", fg(fmt::terminal_color::bright_yellow) | fmt::emphasis::bold));

    try {
        ConnMgr mgr;
        asio::io_context & io_context = mgr.io_context;

        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](std::error_code ec, int sig){
            if (!ec) {
                fmt::print(fg(Color::green)|fmt::emphasis::italic, "\n--- Caught signal {}, exiting ...\n", styled(sig, fg(Color::bright_white)|bg(Color::blue)));
                io_context.stop();
            } else {
                Error("\n--- Sighandler error: {}", styled(ec.message(), fg(Color::bright_white)|bg(Color::blue)));
            }
        });

        size_t errct = 0;

        using HP = std::tuple<Net, std::string_view, uint16_t>;
        std::array hp = {
            HP{Main, "localhost", 8888}, // this should error
            HP{Main, "c3.c3-soft.com", 8333},
            HP{Chip, "c3.c3-soft.com", 48333},
            HP{Main, "bch.loping.net", 8333},
            HP{Main, "tbch.loping.net", 18333}, // this is wrong -- testing error case
            HP{Scale, "sbch.loping.net", 38333},
        };

        auto handler = [&](std::string_view host, uint16_t port, std::exception_ptr exc) {
            if (exc) {
                try {
                    std::rethrow_exception(exc);
                } catch (const std::exception &e) {
                    if (++errct == hp.size())
                        throw;
                    Warning("{}:{}: Exception: {}", host, port, e.what());
                }
            }
        };

        for (const auto & [net, host, port] : hp) {
            co_spawn(io_context, client(&mgr, net, host, port), [&handler, host, port](auto exc) { handler(host, port, exc); });
        }

        io_context.run();
    } catch (std::exception& e) {
        Error("Exception: {}", styled(e.what(), fmt::emphasis::bold|bg(Color::bright_red)|fg(Color::bright_white)));
    }

    return EXIT_SUCCESS;
}
