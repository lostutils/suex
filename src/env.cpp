#include <env.h>
#include <utils.h>
using namespace suex;

char *const *env::Raw() { return environ; };

bool env::Contains(const std::string &env) {
  return std::getenv(env.c_str()) != nullptr;
}

std::string env::Get(const std::string &env) {
  char *val = std::getenv(env.c_str());
  return val == nullptr ? "" : val;
}

char *env::GetRaw(const std::string &env) {
  std::string val{Get(env)};
  std::string raw{utils::StringFormat("%s=%s", env.c_str(), val.c_str())};
  return strdup(raw.c_str());
}

std::pair<std::string, std::string> env::SplitRaw(const std::string &raw_env) {
  char key[raw_env.size()];
  char value[raw_env.size()];

  key[0] = value[0] = '\0';

  int scanned = sscanf(raw_env.c_str(), "%[^=]=%s", key, value);
  if (scanned < 1 || scanned > 2) {
    throw std::runtime_error("couldn't split env");
  }

  return std::pair<std::string, std::string>(key, value);
}

char *env::ToRaw(const std::string &key, const std::string &val) {
  std::string raw = utils::StringFormat("%s=%s", key.c_str(), val.c_str());
  return strdup(raw.c_str());
}
