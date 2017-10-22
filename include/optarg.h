#pragma once
#include <getopt.h>
#include <perm.h>
#include <utils.h>
#include <iostream>
#include <regex>
#include <vector>

namespace suex::optargs {
#define PATH_CONFIG "/etc/suex.conf"
#define DEFAULT_AUTH_SERVICE "su"

class OptArgs {
 public:
  OptArgs(int argc, char *argv[]);

  char *const *CommandArguments() const { return args_.data(); }

  const std::string &ConfigPath() const { return config_path_; }

  const std::string &AuthService() const { return pam_service_; }

  bool Interactive() const { return interactive_; }

  bool ShowVersion() const { return show_version_; }

  bool ClearAuthTokens() const { return clear_auth_tokens_; }

  bool EditConfig() const { return edit_config_; }

  bool VerboseMode() const { return verbose_mode_; }

  bool ShowPermissions() const { return show_perms_; }

  const permissions::User &AsUser() const { return user_; }

 private:
  int ParseOpts(int argc, char *argv[]);

  int GetArgumentCount(int argc, char *argv[]);

  std::string pam_service_{DEFAULT_AUTH_SERVICE};
  std::vector<char *> args_{};
  std::string config_path_;
  std::string binary_;
  bool show_version_{false};
  bool edit_config_{false};
  bool show_perms_{false};
  bool interactive_{true};
  bool clear_auth_tokens_{false};
  bool verbose_mode_{false};
  permissions::User user_{root_user};
};
}
