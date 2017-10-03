#pragma once
#include <string>
#define AUTH_CACHE_DIR "/tmp/.doas"

bool Authenticate(const std::string &service_name);
time_t SetTimestamp(const std::string &filename);
std::string GetFilename(const std::string &txt);
time_t SetTimestamp(const std::string &filename);
