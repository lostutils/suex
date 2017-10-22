#pragma once
#include <string>

namespace doas::auth {

#define PATH_VAR_RUN "/var/run"
#define PATH_DOAS_TMP PATH_VAR_RUN "/doas"
#define PATH_PAM_POlICY "/etc/pam.d"

int ClearTokens(const std::string &service_name);

bool Authenticate(const std::string &service_name,
                  bool prompt,
                  const std::string &cache_token = "");

bool PolicyExists(const std::string &service_name);
}
