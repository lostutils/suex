#include <vector>
#include <getopt.h>
#include <perm.h>
#include <iostream>

#define DEFAULT_CONFIG_PATH "/etc/doas.conf"

static const User running_user = User(getuid());

class Options {
 public:
  Options(int argc, char *argv[]);

  char *const *CommandArguments() const {
    return args_.data();
  }

  const std::string &ConfigurationPath() const { return config_path_; }

  const User &AsUser() const { return user_; }

  const Group &AsGroup() const { return group_; }

 private:
  int Parse(int argc, char **argv);
  void ParsePermissions(const std::string &perms);
  std::vector<char *> args_{};
  std::string config_path_{DEFAULT_CONFIG_PATH};
  std::string binary_{};
  User user_ = User(0);
  Group group_ = Group(0);
};

