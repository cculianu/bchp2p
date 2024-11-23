#pragma once
#include <fmt/printf.h>

#include <concepts>
#include <string_view>
#include <utility>

namespace bitcoin {

template <std::convertible_to<std::string_view> S, typename ...Args>
auto strprintf(const S & fmt, Args &&...args) { return fmt::sprintf(fmt, std::forward<Args>(args)...); }

} // namespace bitcoin
