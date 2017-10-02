#include <sstream>
#include <zconf.h>
#include <path.h>
#include "options.h"

Options::Options(int argc, char *argv[]) {
    int idx = parse(argc, argv);
    _args = std::vector<char *> {argv + idx, argv + argc};
    // low level c code needs an indication when an array of pointers ends
    _args.emplace_back((char *) nullptr);
    //

    _args.emplace(_args.begin() + 1, (char*) getpath(_args.front(), true).c_str());
    _args.erase(_args.begin());
}

int Options::parse(int argc, char *argv[]) {
    int app_argc, c;
    User running_user{getuid()};

    for (app_argc = 1; app_argc < argc; ++app_argc) {
        if (argv[app_argc][0] != '-') {
            break;
        }
    }

    while (true) {
        c = getopt(app_argc + 1, argv, "u:");

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
            case 'u': {

                const std::string perms(optarg);
                // extract the username and group
                // if <username>:<group-name> passed, update username string to <username>
                unsigned long delimIdx = perms.find(':');
                const std::string grpname(delimIdx != perms.npos ? perms.substr(delimIdx + 1) : "");
                const std::string username = grpname.empty() ? perms : perms.substr(0, delimIdx);
                _user = User(username);

                if (!_user.exists()) {
                    std::stringstream ss;
                    ss << "'" << running_user.name() << "' can't run: user '" << username << "' doesn't exist";
                    throw std::runtime_error(ss.str());
                }

                // load destination group and check that it exists
                _group = Group(grpname, _user);
                if (!_group.exists()) {
                    std::stringstream ss;
                    ss << "'" << running_user.name() << "' can't run: group '" << grpname << " ""' doesn't exist";
                    throw std::runtime_error(ss.str());
                }

                break;
            }
            case '?':
                break;
            default:
                abort();
        }
    }
    return optind;
}

