//
// refactored_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2024 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "util.h"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/signal_set.hpp>
#include <asio/write.hpp>

#include <cstdint>
#include <charconv>
#include <system_error>

using asio::ip::tcp;
using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
namespace this_coro = asio::this_coro;

template <typename T = void, typename E = asio::any_io_executor>
using async = awaitable<T, E>; // make it look a little more like Python? ;)

async<> echo_once(tcp::socket & socket)
{
    char data[128];
    std::size_t n = co_await socket.async_read_some(asio::buffer(data), use_awaitable);
    co_await async_write(socket, asio::buffer(data, n), use_awaitable);
}

async<> echo(tcp::socket socket)
{
    auto addrport = fmt::format("{}:{}", socket.remote_endpoint().address().to_string(), socket.remote_endpoint().port());
    addrport = fmt::format("{}", styled(addrport, fmt::emphasis::underline|fg(Color::bright_white)|bg(Color::green)));
    Log("Connection from: {} ...", addrport);
    Defer d([&]{ Debug("{} ended", addrport); });
    try
    {
        for (;;)
        {
            // The asynchronous operations to echo a single chunk of data have been
            // refactored into a separate function. When this function is called, the
            // operations are still performed in the context of the current
            // coroutine, and the behaviour is functionally equivalent.
            co_await echo_once(socket);
        }
    }
    catch (std::exception& e)
    {
        Error("echo Exception: {}", styled(e.what(), fmt::emphasis::bold|bg(Color::bright_red)|fg(Color::bright_white)));
    }
}

async<> listener(uint16_t port)
{
    Defer d([]{ Debug("{} end", styled("listener", fg(Color::bright_yellow))); });
    auto executor = co_await this_coro::executor;
    tcp::acceptor acceptor(executor, {tcp::v4(), port});
    Log(fg(Color::bright_white), "Listening on: {}:{} ...", acceptor.local_endpoint().address().to_string(), acceptor.local_endpoint().port());
    for (;;)
    {
        tcp::socket socket = co_await acceptor.async_accept(use_awaitable);
        if (socket.is_open())
            co_spawn(executor, echo(std::move(socket)), detached);
        else
            Warning("Socket not open!");
    }
}

int main(int argc, char *argv[])
{
    Debug::enabled = true;

    try
    {
        uint16_t port = 0; // let OS pick a port
        if (argc > 1) {
            // user specified a port, parse
            if (auto ec = std::from_chars(argv[1], std::string_view{argv[1]}.end(), port).ec; bool(ec)) {
                throw std::invalid_argument(fmt::format("Bad arg '{}': {}", argv[1], std::make_error_code(ec).message()));
            }
        }
        asio::io_context io_context(1);

        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&](std::error_code ec, int sig){
            if (!ec) {
                fmt::print(fg(Color::green)|fmt::emphasis::italic, "\n--- Caught signal {}, exiting ...\n", styled(sig, fg(Color::bright_white)|bg(Color::blue)));
                io_context.stop();
            } else {
                Error("\n--- Sighandler error: {}", styled(ec.message(), fg(Color::bright_white)|bg(Color::blue)));
            }
        });

        co_spawn(io_context, listener(port), [&](std::exception_ptr ep){
            if (ep) std::rethrow_exception(ep);
            io_context.stop();
        });

        io_context.run();
    }
    catch (std::exception& e)
    {
        Error("Exception: {}", styled(e.what(), fmt::emphasis::bold|bg(Color::bright_red)|fg(Color::bright_white)));
    }
}
