#pragma once

#include <string>
#define PATH_DEV_NULL "/dev/null"

namespace suex::utils::path {

bool Exists(const std::string &path);

const std::string Real(const std::string &path);

const std::string Locate(const std::string &path, bool searchInPath = true);
}
