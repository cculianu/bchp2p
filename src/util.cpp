#include "util.h"

#include <string>
#include <string_view>

Log::Log(bool b, fmt::string_view format, fmt::format_args args, std::optional<fmt::text_style> ots)
    : en(b), ots(ots)
{
    if (en) fmt::vprint(os, format, args);
}

Log::~Log()
{
    if (!en) return;
    const std::string s = std::move(os).str();
    // just print to stdout.. for now. auto-append NL if none appended
    using namespace std::string_view_literals;
    std::string_view nl = !s.ends_with('\n') ? "\n"sv : ""sv;
    if (ots) {
        fmt::print(*ots, "{}{}"sv, s, nl);
    } else {
        fmt::print("{}{}"sv, s, nl);
    }
}

/* static */ std::atomic_bool Debug::enabled = false;
