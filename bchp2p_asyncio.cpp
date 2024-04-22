#include "bitcoin/hash.h"
#include "bitcoin/logging.h"
#include "bitcoin/protocol.h"
#include "bitcoin/streams.h"
#include "bitcoin/random.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin/utiltime.h"

#include <asyncio/finally.h>
#include <asyncio/gather.h>
#include <asyncio/noncopyable.h>
#include <asyncio/open_connection.h>
#include <asyncio/runner.h>
#include <asyncio/sleep.h>
#include <asyncio/start_server.h>
#include <asyncio/stream.h>
#include <asyncio/task.h>

#include <fmt/format.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <span>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <arpa/inet.h>


using namespace asyncio;
using namespace std::string_view_literals;

struct ProtocolError : std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class Connection;

struct ConnMgr {
    int &fd;

    ConnMgr(int &fd) : fd(fd) {}

    std::set<Connection *> conns;

    void add(Connection *c) { conns.insert(c); }
    void rm(Connection *c) {
        conns.erase(c);
        if (conns.empty()) {
            const int val = -1;
            auto sp = std::as_bytes(std::span(&val, 1));
            ::write(fd, sp.data(), sp.size_bytes());
        }
    }
};

class Connection : NonCopyable
{
    ConnMgr * const mgr;
    asyncio::Stream sock;
    bitcoin::CAddress local, remote;
    const bool inbound;
    const bitcoin::CMessageHeader::MessageMagic magic;
    const uint64_t nLocalNonce;
    bitcoin::Tic tstart;
    bool disconnectRequested = false;

    std::map<std::string_view, size_t> msgByteCountsIn, msgByteCountsOut, msgCountsIn{}, msgCountsOut{};
    size_t bytesIn{}, bytesOut{}, msgsIn{}, msgsOut{};

    int protoVersion = bitcoin::INIT_PROTO_VERSION;
    std::string cleanSubVer;
    bool sentVersion = false, sentVerAck = false, gotVersion = false, gotVerAck = false, didAfterHandshake = false;
    bool relay = false;
    int misbehavior = 0;
    static constexpr int MAX_MISBEHAVIOR = 100;

    [[nodiscard]]
    Task<> MsgHandler(bitcoin::CSerializedNetMsg msg);

    [[nodiscard]] Task<> SendVersion();
    [[nodiscard]] Task<> SendVerACK(int nVersion = 0);
    [[nodiscard]] Task<> Send(bitcoin::CSerializedNetMsg msg);
    template <typename ...Args>
    [[nodiscard]] Task<> Send(std::string_view msg_type, Args ...args) {
        using namespace bitcoin;
        co_await Send(CNetMsgMaker(protoVersion).Make(msg_type, std::forward<Args>(args)...));
    }

    [[nodiscard]] Task<> HandleVersion(bitcoin::CSerializedNetMsg msg);
    [[nodiscard]] Task<> HandlePing(bitcoin::CSerializedNetMsg msg);
    [[nodiscard]] Task<> HandlePong(bitcoin::CSerializedNetMsg msg);

    [[nodiscard]] Task<> DoOnceIfAfterHandshake(); // does GETADDR, etc -- stuff we do immediately after a state change to "fully established"

    static constexpr int pingIntervalSecs = 30;
    uint64_t lastPingNonceSent = 0;
    int64_t lastPingTSMillis = 0, lastPongTSMillis = 0, lastPingPongDelta = 0;
    [[nodiscard]] Task<> Pinger(); // periodically pings node every 60 seconds

    std::string GetInfoStr() const {
        const int64_t nTimeMicros = bitcoin::GetTimeMicros();
        std::string dtstr = bitcoin::FormatISO8601DateTime(nTimeMicros / 1'000'000);
        if (dtstr.back() == 'Z') dtstr.pop_back();
        dtstr += fmt::format(".{:06d}Z", nTimeMicros % 1'000'000);
        return fmt::format("{} {}", dtstr, remote.ToStringIPPort()); // this is a hack
    }

    void Misbehaving(int score, std::string_view msg);

    using ST = ScheduledTask<Task<>>;
    std::unique_ptr<ST> disconnector, pinger;

public:
    Connection(ConnMgr *mgr, asyncio::Stream &&s_, bool inbound_, const bitcoin::CMessageHeader::MessageMagic &magic_)
        : mgr(mgr), sock(std::move(s_)), inbound(inbound_), magic(magic_), nLocalNonce(bitcoin::GetRand64())
    {
        mgr->add(this);
        bitcoin::CService srv;
        std::visit([&](const auto &s){ srv = bitcoin::CService(s); }, sock.get_sockaddr(false));
        local = bitcoin::CAddress(srv, bitcoin::ServiceFlags(bitcoin::NODE_BITCOIN_CASH|bitcoin::NODE_NETWORK|bitcoin::NODE_BLOOM),
                                  bitcoin::GetTime());
        std::visit([&](const auto &s){ srv = bitcoin::CService(s); }, sock.get_sockaddr(true));
        remote = bitcoin::CAddress(srv, bitcoin::ServiceFlags::NODE_NONE, bitcoin::GetTime());
    }

    Connection(Connection &&) = delete;

    ~Connection() { mgr->rm(this); }

    [[nodiscard]]
    Task<> ProcessLoop();

    [[nodiscard]]
    Task<> CancelProcessing() {
        fmt::print("{}: Canceling processing ...\n", GetInfoStr());
        disconnectRequested = true;
        fmt::print("{}: shutdown ...\n", GetInfoStr());
        sock.shutdown();
        pinger.reset();
        co_await sleep(std::chrono::milliseconds{10});
        fmt::print("{}: close ...\n", GetInfoStr());
        sock.close();
    }

    void scheduleDisconnect() {
        if (!disconnectRequested) {
            disconnectRequested = true;
            disconnector = std::make_unique<ST>(schedule_task(CancelProcessing()));
        }
    }

    void schedulePinger() { pinger = std::make_unique<ST>(schedule_task(Pinger())); }

    bool isFullyConnected() const { return sentVersion && sentVerAck && gotVersion && gotVerAck; }
};

Task<> Connection::SendVersion()
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

Task<> Connection::SendVerACK(int nVersion)
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

Task<> Connection::Send(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    CMessageHeader hdr(magic, msg); // construct valid header with checksum
    std::vector<uint8_t> hdrdata;
    VectorWriter(SER_NETWORK, PROTOCOL_VERSION, hdrdata, 0) << hdr;
    const size_t msgSize = hdrdata.size() + msg.data.size();
    const auto cmd = hdr.GetCommand();
    fmt::print("{}: Sending msg {} {} bytes\n", GetInfoStr(), cmd, msgSize);
    const auto ncmd = NetMsgType::Normalize(cmd); // assumption: Normalize() returns a long-lived string_view!
    msgByteCountsOut[ncmd] += msgSize;
    ++msgCountsOut[ncmd];
    bytesOut += msgSize;
    ++msgsOut;
    Tic t0;
    co_await sock.write(hdrdata); // send header
    co_await sock.write(msg.data); // send payload
    fmt::print("{}: {} msec for '{}' xfer\n", GetInfoStr(), t0.msecStr(), ncmd);
}

Task<> Connection::ProcessLoop()
{
    tstart = bitcoin::Tic();
    fmt::print("{}: Connected\n", GetInfoStr());
    finally { fmt::print("{}: ProcessLoop ended, {} secs elapsed\n", GetInfoStr(), tstart.secsStr(3)); };
    if (!inbound) {
        // first thing we must do is send the version
        co_await SendVersion();
    }
    using namespace bitcoin;
    using Hdr = CMessageHeader;
    try {
        while ( ! disconnectRequested) {
            auto data = co_await sock.read<std::string>(Hdr::HEADER_SIZE, true);
            if (data.empty()) {
                fmt::print("{}: EOF\n", GetInfoStr());
                break;
            }
            if (data.size() != Hdr::HEADER_SIZE) throw ProtocolError("Short header read");
            Hdr hdr({});
            GenericVectorReader(SER_NETWORK, protoVersion, data, 0) >> hdr;
            if (!hdr.IsValid(magic)) throw ProtocolError("Bad header");
            CSerializedNetMsg msg;
            msg.m_type = hdr.GetCommand();
            msg.data = co_await sock.read<std::vector<uint8_t>>(hdr.nMessageSize, true);
            if (msg.data.size() != hdr.nMessageSize) throw ProtocolError("Short payload read");
            if (Span(Hash(msg.data)).first(hdr.CHECKSUM_SIZE) != Span(hdr.pchChecksum)) throw ProtocolError("Bad checksum");
            co_await MsgHandler(std::move(msg));
        }
    } catch (const std::exception &e) {
        fmt::print("{}: Exception: {}\n", GetInfoStr(), e.what());
    }
}

void Connection::Misbehaving(int howmuch, std::string_view msg)
{
    misbehavior += howmuch;
    fmt::print("{}: {}: ({} -> {}) reason: {}\n", GetInfoStr(), __func__,  misbehavior - howmuch, misbehavior, msg);
    if (misbehavior >= MAX_MISBEHAVIOR) {
        scheduleDisconnect();
    }
}

Task<> Connection::MsgHandler(bitcoin::CSerializedNetMsg msg)
{
    using namespace bitcoin;
    Tic t0;
    const size_t msize = msg.data.size() + CMessageHeader::HEADER_SIZE;
    fmt::print("{}: Got message: {}, size: {}\n", GetInfoStr(), msg.m_type, msize);
    // tally byte counts. Note: Normalize() should return a "peristent" string_view for this to not be UB!
    std::string_view const ncmd = NetMsgType::Normalize(msg.m_type);
    msgByteCountsIn[ncmd] += msize;
    ++msgCountsIn[ncmd];
    bytesIn += msize;
    ++msgsIn;

    finally {
        fmt::print("{}: Handled '{}' in {} msec\n", GetInfoStr(), ncmd, t0.msecStr());
    };

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

Task<> Connection::HandleVersion(bitcoin::CSerializedNetMsg msg)
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
        fmt::print("{}: peer using obsolete version {}; disconnecting\n", GetInfoStr(), nVersion);
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
        fmt::print("{}: Got subversion: {}\n", GetInfoStr(), cleanSubVer);
    }
    if (!vRecv.empty()) {
        vRecv >> nStartingHeight;
    }
    if (!vRecv.empty()) {
        vRecv >> this->relay;
    }

   // Disconnect if we connected to self
    if (nNonce && inbound && nNonce == nLocalNonce) {
        fmt::print("{}: connected to self, disconnecting\n", GetInfoStr());
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

Task<> Connection::DoOnceIfAfterHandshake() {
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

Task<> Connection::HandlePing(bitcoin::CSerializedNetMsg msg)
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

Task<> Connection::HandlePong(bitcoin::CSerializedNetMsg msg)
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
                fmt::print("{}: Valid ping reply, measured latency: {:1.3f} msec\n", GetInfoStr(), lastPingPongDelta / 1e3);
            } else {
                problem = fmt::format("Ping reply nonce ({:x}) != what we expected ({:x})", nonce, lastPingNonceSent);
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

Task<> Connection::Pinger()
{
    using namespace bitcoin;
    fmt::print("{}: Pinger started\n", GetInfoStr());
    finally { fmt::print("{}: Pinger stopped\n", GetInfoStr()); };

    while (!disconnectRequested) {
        // sleep 5 secs if not yet fully connected or 30 otherwise
        co_await asyncio::sleep(std::chrono::seconds{isFullyConnected() ? pingIntervalSecs : 5});
        fmt::print("{}: Pinger wakeup ..\n", GetInfoStr());
        if (isFullyConnected()) {
            if (lastPingTSMillis && /* test for neg. below 1 sec: */ lastPongTSMillis - lastPingTSMillis < -1'000'000) {
                Misbehaving(10, "No recent ping reply");
            }
            do { lastPingNonceSent = GetRand64(); } while (!lastPingNonceSent);
            lastPingTSMillis = GetTimeMillis();
            co_await Send(NetMsgType::PING, lastPingNonceSent);
        }
    }
}

Task<> client(ConnMgr *mgr, std::string hostname, uint16_t port) {
    auto stream = co_await asyncio::open_connection(hostname, port);
    const bitcoin::CMessageHeader::MessageMagic magic = {
        ///* chipnet: */ 0xe2, 0xb7, 0xda, 0xaf,
        /* mainnet: */ 0xe3, 0xe1, 0xf3, 0xe8,
    };
    Connection conn(mgr, std::move(stream), false, magic);
    co_await conn.ProcessLoop();
}

int pipe_fds[2] = {-1, -1};

extern "C" void sighandler(int sig)
{
    constexpr auto msg = "\n -- Caught signal, exiting ...\n"sv;
    ::write(2, msg.data(), msg.size());
    auto sp = std::as_bytes(std::span(&sig, 1));
    ::write(pipe_fds[1], sp.data(), sp.size_bytes());
}

Task<> SigCatcher(ConnMgr *mgr) {
    Event ev { .fd = pipe_fds[0], .flags = Event::Flags::EVENT_READ };
    auto& loop = get_event_loop();
    std::string_view func = __func__;
    co_await loop.wait_event(ev);
    fmt::print("{}: Wakeup ...\n", func);
    finally { fmt::print("{}: exit\n", func); };
    int sig = 0;
    auto sp = std::as_writable_bytes(std::span(&sig, 1));
    ::read(pipe_fds[0], sp.data(), sp.size_bytes());
    if ( ! mgr->conns.empty()) {
        fmt::print("{}: Got sig {}, killing {} conns ...\n", func, sig, mgr->conns.size());
        for (auto * conn : mgr->conns) {
            conn->scheduleDisconnect();
        }
    }
}

int main() {
    if (::pipe(pipe_fds) != 0) {
        std::perror("pipe");
        return EXIT_FAILURE;
    }
    finally { for (int & fd : pipe_fds) { ::close(fd); fd = -1; } };
    bitcoin::LogInstance().m_log_timestamps = bitcoin::LogInstance().m_log_time_micros = true;
    std::signal(SIGPIPE, SIG_IGN); // required to avoid SIGPIPE when write()/read()
    std::signal(SIGINT, sighandler);
    std::signal(SIGTERM, sighandler);
    bitcoin::RandomInit();
    if (!bitcoin::Random_SanityCheck()) fmt::print(stderr, "WARNING: Random_SanityCheck failed!\n");

    ConnMgr mgr(pipe_fds[1]);
    try {
        asyncio::run(asyncio::gather(//client(&mgr, "localhost", 8888),
                                     client(&mgr, "c3.c3-soft.com", 8333),
                                     client(&mgr, "c3.c3-soft.com", 48333),
                                     SigCatcher(&mgr)));
    } catch (const asyncio::NoResultError &) {} // ignore. Bug in gather()

    return EXIT_SUCCESS;
}
