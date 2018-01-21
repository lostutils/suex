#include <env.hpp>
#include <fmt.hpp>
#include <sstream>
#include <utils.hpp>

char **suex::env::Raw() { return environ; };

bool suex::env::Contains(const std::string &env) {
  return std::getenv(env.c_str()) != nullptr;
}

std::string suex::env::Get(const std::string &env) {
  char *val = std::getenv(env.c_str());
  return val == nullptr ? "" : val;
}

char *suex::env::GetRaw(const std::string &env) {
  std::string val{Get(env)};
  std::string raw{Sprintf("%s=%s", env.c_str(), val.c_str())};
  return strdup(raw.c_str());
}

std::pair<std::string, std::string> suex::env::SplitRaw(
    const std::string &raw_env) {
  std::istringstream ss{raw_env};
  std::string key, value;

  if (!std::getline(ss, key, '=')) {
    std::runtime_error("Couldn't extract key");
  }
  if (!std::getline(ss, value)) {
    std::runtime_error("Couldn't extract value");
  }

  return std::make_pair(key, value);
}

char *suex::env::ToRaw(const std::string &key, const std::string &val) {
  std::string raw{Sprintf("%s=%s", key.c_str(), val.c_str())};
  return strdup(raw.c_str());
}
