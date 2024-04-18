#pragma once
#include <fmt/printf.h>

#include <utility>

namespace bitcoin {

template <typename ...Args>
auto strprintf(Args &&...args) { return fmt::sprintf(std::forward<Args>(args)...); }

} // namespace bitcoin
