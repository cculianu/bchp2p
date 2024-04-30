#pragma once

#include <string>
#include <string_view>

class UniValue;

namespace html_bits {

std::string MakePrettyHtmlForJson(std::string_view docTitle, const UniValue &json);

} // namespace html_bits
