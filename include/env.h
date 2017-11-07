#pragma once

#include <string>
#include <unordered_map>

namespace suex::env {
char **Raw();
std::string Get(const std::string &env);
char *GetRaw(const std::string &env);
bool Contains(const std::string &env);
std::pair<std::string, std::string> SplitRaw(const std::string &raw_env);
char *ToRaw(const std::string &key, const std::string &val);
}