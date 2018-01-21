#pragma once

#include <string>
#define PATH_DEV_NULL "/dev/null"
#define PATH_TMP "/tmp"

namespace suex::utils::path {

bool Exists(const std::string &path);

const std::string Readlink(int fd);

const std::string GetPath(int fd);

const std::string Locate(const std::string &path, bool searchInPath = true);
}  // namespace suex::utils::path
