#include "util.h"

#include "bitcoin/logging.h" // HACK! We rely on the bitcoin logger here for now (to get the consistent timestamps, etc)

#include <string>
#include <string_view>

Log::Log(bool b, fmt::string_view format, fmt::format_args args, std::optional<fmt::text_style> ots)
    : en(b), ots(ots)
{
    if (en) {
        if (format.size() > 0u && format[format.size() - 1u] == '\n')
            // pop the trailing \n off, since we append one anyway at the end
            format = fmt::string_view{format.data(), format.size() - 1u};
        fmt::vprint(os, format, args);
    }
}

Log::~Log()
{
    if (!en) return;
    std::string s = std::move(os).str();
    // just print to stdout.. for now. auto-append NL if none appended
    using namespace std::string_view_literals;
    if (ots) {
        s = fmt::format(*ots, "{}"sv, s);
    }
    bitcoin::LogPrintf("%s\n"sv, s);
}

/* static */ std::atomic_bool Debug::enabled = false;
