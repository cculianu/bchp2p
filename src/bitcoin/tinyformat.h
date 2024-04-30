#pragma once
#include <fmt/printf.h>

#include <string_view>
#include <utility>

namespace bitcoin {

template <typename ...Args>
auto strprintf(std::string_view fmt, Args &&...args) { return fmt::sprintf(fmt, std::forward<Args>(args)...); }

} // namespace bitcoin
