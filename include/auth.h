#pragma once
#include <string>
#define AUTH_CACHE_DIR "/tmp/.doas"

bool Authenticate(const std::string &service_name, bool cache);
