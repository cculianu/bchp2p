#pragma once

#include <atomic>
#include <concepts>
#include <optional>
#include <sstream>
#include <utility>

#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/ostream.h>

template <std::invocable F>
struct Defer
{
    Defer(F && f) : func(std::move(f)) {}
    Defer(const F & f) : func(f) {}
    /// move c'tor -- invalidate other, take its function.
    Defer(Defer && o) : func(std::move(o.func)), valid(o.valid) { o.valid = false; }
    /// d'tor -- call wrapped func. if we are still valid.
    ~Defer() { if (valid) func(); }

    /// Mark this instance as a no-op. After a call to disable, this Defer instance  will no longer call its wrapped
    /// function upon descruction.  This operation cannot be reversed.
    void disable() { valid = false; }
protected:
    F func;
    bool valid = true;
};

using Color = fmt::terminal_color;

class Log {
    std::ostringstream os;
    bool en = true;
    std::optional<fmt::text_style> ots;
public:
    Log(std::optional<fmt::text_style> ots = std::nullopt) : ots(ots) {}

    template <typename ...Args>
    Log(fmt::format_string<Args...> format, Args && ...args) : Log(true, format.get(), fmt::make_format_args(args...)) {}

    template <typename ...Args>
    Log(fmt::text_style ts, fmt::format_string<Args...> format, Args && ...args) : Log(true, format.get(), fmt::make_format_args(args...), ts) {}

    template <typename ...Args>
    Log(Color c, fmt::format_string<Args...> format, Args && ...args) : Log(true, format.get(), fmt::make_format_args(args...), fg(c)) {}

    ~Log();

    Log(Log &&o) noexcept : os{std::move(o.os)}, en{o.en}, ots{std::move(o.ots)} { o.en = false; }
    Log &operator=(Log &&o) noexcept { os.swap(o.os);  en = o.en; ots = std::move(o.ots); o.en = false; return *this; }

    // Note: This style may be slower (if repeatedly called) than simply formatting with a format string
    template <typename T>
    Log & operator<<(T && t) { if (en) fmt::print(os, "{}", std::forward<T>(t)); return *this; }

protected:
    Log(bool b, fmt::string_view format, fmt::format_args args, std::optional<fmt::text_style> = std::nullopt);
};

struct Debug : Log {
    Debug() : Debug("") {}

    template <typename ...Args>
    Debug(fmt::format_string<Args...> format, Args && ...args)
        : Log(enabled.load(std::memory_order_relaxed), format, fmt::make_format_args(args...), fg(Color::cyan)) {}

    template <typename ...Args>
    Debug(fmt::text_style ts, fmt::format_string<Args...> format, Args && ...args)
        : Log(enabled.load(std::memory_order_relaxed), format, fmt::make_format_args(args...), ts) {}

    template <typename ...Args>
    Debug(Color c, fmt::format_string<Args...> format, Args && ...args)
        : Debug(fg(c), format, std::forward<Args>(args)...) {}

    static std::atomic_bool enabled;
};

struct Error : Log {
    Error() : Error("") {}

    template <typename ...Args>
    Error(fmt::format_string<Args...> format, Args && ...args)
        : Log(true, format, fmt::make_format_args(args...), fg(Color::bright_magenta)) {}

    template <typename ...Args>
    Error(fmt::text_style ts, fmt::format_string<Args...> format, Args && ...args)
        : Log(true, format, fmt::make_format_args(args...), ts) {}

    template <typename ...Args>
    Error(Color c, fmt::format_string<Args...> format, Args && ...args)
        : Error(fg(c), format, std::forward<Args>(args)...) {}
};

struct Warning : Log {
    Warning() : Warning("") {}

    template <typename ...Args>
    Warning(fmt::format_string<Args...> format, Args && ...args)
        : Log(true, format, fmt::make_format_args(args...), fg(Color::bright_yellow)) {}

    template <typename ...Args>
    Warning(fmt::text_style ts, fmt::format_string<Args...> format, Args && ...args)
        : Log(true, format, fmt::make_format_args(args...), ts) {}

    template <typename ...Args>
    Warning(Color c, fmt::format_string<Args...> format, Args && ...args)
        : Warning(fg(c), format, std::forward<Args>(args)...) {}
};
