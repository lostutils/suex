#include <env.h>
Environment::Environment(char *const envp[]) : raw_envp_{envp} {
  for (char *const *it = envp; *it != nullptr; ++it) {
    std::string env{*it};
    unsigned long idx{env.find('=')};
    envp_.emplace(env.substr(0, idx), env.substr(idx + 1));
  }
}

bool Environment::Contains(std::string &env) const {
  auto it = envp_.find(env);
  return it == envp_.end();
}
std::string Environment::Get(std::string env) const {
  auto it = envp_.find(env);
  if (it == envp_.end()) {
    throw std::range_error("env doesn't exist");
  }
  return it->second;
}
