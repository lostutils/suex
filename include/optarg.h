#pragma once
#include <getopt.h>
#include <perm.h>
#include <utils.h>
#include <gsl/span>
#include <iostream>
#include <vector>

namespace suex::optargs {
#define PATH_CONFIG "/etc/suex.conf"
#define DEFAULT_AUTH_STYLE "su"

class OptArgs {
 public:
  OptArgs(int argc, char *argv[]);

  const std::vector<char *> &CommandArguments() const { return args_; }

  const std::string &ConfigPath() const { return config_path_; }

  const std::string &AuthStyle() const { return auth_style_; }

  bool Interactive() const { return interactive_; }

  bool ShowVersion() const { return show_version_; }

  bool Clear() const { return clear_; }

  bool EditConfig() const { return edit_config_; }

  bool VerboseMode() const { return verbose_mode_; }

  bool ListPermissions() const { return list_; }

  const permissions::User &AsUser() const { return user_; }

 private:
  int ParseOpts(int argc, char *argv[]);

  int GetArgumentCount(int argc, char *argv[]);

  std::string auth_style_{DEFAULT_AUTH_STYLE};
  std::vector<char *> args_{};
  std::string config_path_;
  std::string binary_;
  bool show_version_{false};
  bool edit_config_{false};
  bool list_{false};
  bool interactive_{true};
  bool clear_{false};
  bool verbose_mode_{false};
  permissions::User user_{RootUser()};
};
}
