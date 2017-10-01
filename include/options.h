#include <vector>
#include <getopt.h>
#include <perm.h>
#include <iostream>

class Options {
public:
    Options(int argc, char *argv[]);

    const std::vector<char *> cmdargv() const {
        return _args;
    }

    User& me() { return _me; }

    User& as_user() { return _user; }

    Group& as_group() { return _group; }

private:
    int parse(int argc, char *argv[]);

    std::vector<char *> _args{};
    std::string _cmd {};
    User _me = User(getuid());
    User _user = User(0);
    Group _group = Group(0);
};
