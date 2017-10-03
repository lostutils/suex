#pragma once

#include <string>
#include <unordered_map>

class Environment {
 public:
  explicit Environment(char *const envp[]);
  char *const * Raw()const { return raw_envp_; };
  std::string Get(std::string env) const;
  bool Contains(std::string &env) const;

 private:
  std::unordered_map<std::string, std::string> envp_;
  char *const *raw_envp_;

};
