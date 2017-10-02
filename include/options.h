#include <vector>
#include <getopt.h>
#include <perm.h>
#include <iostream>

#define DEFAULT_CONFIG_PATH "/etc/doas.conf"

class Options {
public:
    Options(int argc, char *argv[]);

    char *const * CommandArguments() const {
        return args_.data();
    }

    std::string &ConfigurationPath() { return config_path_;  }

    User& Me() { return me_; }

    User& AsUser() { return user_; }

    Group& AsGroup() { return group_; }

private:
    int Parse(int argc, char **argv);
    void ParsePermissions(const std::string &perms);
    std::vector<char *> args_{};
    std::string config_path_ { DEFAULT_CONFIG_PATH };
    std::string binary_{};
    User me_ = User(getuid());
    User user_ = User(0);
    Group group_ = Group(0);
};
