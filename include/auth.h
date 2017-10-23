#pragma once
#include <string>

namespace suex::auth {

#define PATH_VAR_RUN "/var/run"
#define PATH_SUEX_TMP PATH_VAR_RUN "/suex"
#define PATH_PAM_POlICY "/etc/pam.d"

int ClearTokens(const std::string &service_name);

bool Authenticate(const std::string &service_name, bool prompt,
                  const std::string &cache_token = "");

bool PolicyExists(const std::string &service_name);
}  // namespace suex::auth
