// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tinyformat.h"
#include "utiltime.h"

#include <atomic>
#include <cassert>
#include <ctime>
#include <thread>

#include <time.h>

namespace bitcoin {

void UninterruptibleSleep(const std::chrono::microseconds &n) {
    std::this_thread::sleep_for(n);
}

//! For unit testing
static std::atomic<int64_t> nMockTime(0);

int64_t GetTime() {
    int64_t mocktime = nMockTime.load(std::memory_order_relaxed);
    if (mocktime) {
        return mocktime;
    }

    time_t now = std::time(nullptr);
    assert(now > 0);
    return now;
}

template <typename T> T GetTime() {
    const std::chrono::seconds mocktime{
        nMockTime.load(std::memory_order_relaxed)};

    return std::chrono::duration_cast<T>(
        mocktime.count() ? mocktime
                         : std::chrono::microseconds{GetTimeMicros()});
}
template std::chrono::seconds GetTime();
template std::chrono::milliseconds GetTime();
template std::chrono::microseconds GetTime();

void SetMockTime(int64_t nMockTimeIn) {
    assert(nMockTimeIn >= 0);
    nMockTime.store(nMockTimeIn, std::memory_order_relaxed);
}

int64_t GetMockTime() {
    return nMockTime.load(std::memory_order_relaxed);
}

int64_t GetTimeMillis() {
    auto ts = std::chrono::high_resolution_clock::now();
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(ts.time_since_epoch()).count();
    assert(now > 0);
    return now;
}

int64_t GetTimeMicros() {
    auto ts = std::chrono::high_resolution_clock::now();
    int64_t now = std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count();
    assert(now > 0);
    return now;
}

int64_t GetPerfTimeNanos() {
    // Get the best clock we can from the implementation, prefering high resolution clocks
    // to the 'steady_clock' (but only if it is steady).
    using Clock = std::conditional_t<std::chrono::high_resolution_clock::is_steady,
                                     std::chrono::high_resolution_clock,
                                     std::chrono::steady_clock>;
    // Ensure compiler and C++ library provide the microsecond or better precision we need. If not, fall-back to
    // good old GetTimeMicros().
    if constexpr (std::ratio_less_equal_v<Clock::period, std::micro>) {
        // Save the timestamp of the first time through here to start with low values after app init.
        static const auto t0 = Clock::now();
        return std::chrono::duration<int64_t, std::nano>(Clock::now() - t0).count();
    } else {
        // This branch really should never be taken on the major platforms we support and is normally compiled-out.
        return GetTimeMicros() * 1'000;
    }
}

int64_t GetSystemTimeInSeconds() {
    return GetTimeMicros() / 1000000;
}

void MilliSleep(int64_t n) noexcept {
    std::this_thread::sleep_for(std::chrono::milliseconds(n));
}

std::string FormatISO8601DateTime(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef _WIN32
    gmtime_s(&ts, &time_val);
#else
    gmtime_r(&time_val, &ts);
#endif
    return strprintf("%04i-%02i-%02iT%02i:%02i:%02iZ", ts.tm_year + 1900,
                     ts.tm_mon + 1, ts.tm_mday, ts.tm_hour, ts.tm_min,
                     ts.tm_sec);
}

std::string FormatISO8601Date(int64_t nTime) {
    struct tm ts;
    time_t time_val = nTime;
#ifdef _WIN32
    gmtime_s(&ts, &time_val);
#else
    gmtime_r(&time_val, &ts);
#endif
    return strprintf("%04i-%02i-%02i", ts.tm_year + 1900, ts.tm_mon + 1,
                     ts.tm_mday);
}

std::string Tic::format(double val, int precision) const { return strprintf("%1.*f", precision, val); }
std::string Tic::format(int64_t nsec) const { return strprintf("%i", nsec); }

} // namespace bitcoin
