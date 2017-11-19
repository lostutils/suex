#pragma once

#include <re2/re2/re2.h>
#include "conf.h"
namespace suex::utils::rx {
typedef std::unordered_map<std::string, std::string> Matches;
bool NamedFullMatch(const re2::RE2 &rx, const std::string &line,
                    utils::rx::Matches *matches);
}
