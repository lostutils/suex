#include <sstream>
#include <zconf.h>
#include <path.h>
#include <cstring>
#include "options.h"

Options::Options(int argc, char *argv[]) {
  int idx = Parse(argc, argv);
  args_ = std::vector<char *> {argv + idx, argv + argc};
  // low level c code needs an indication when an array of pointers ends
  args_.emplace_back((char *) nullptr);
  binary_ = GetPath(args_.front(), true);
  args_.front() = (char *) binary_.c_str();
}

int Options::Parse(int argc, char **argv) {
  int app_argc, c;

  for (app_argc = 1; app_argc < argc; ++app_argc) {
    if (argv[app_argc][0] != '-') {
      break;
    }
  }

  while (true) {
    c = getopt(app_argc + 1, argv, "u:C:Lns");

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c) {
      case 'u': {
        ParsePermissions(optarg);
        break;
      }
      case 'C': {
        config_path_ = std::string(optarg);
      }

      case '?':break;
      default:abort();
    }
  }

  return optind;
}

void Options::ParsePermissions(const std::string &username) {

  // extract the username and group
  user_ = User(username);

  if (!user_.Exists()) {
    std::stringstream ss;
    ss << "'" << user_.Name() << "' can't run: user '" << username << "' doesn't exist";
    throw std::runtime_error(ss.str());
  }
}

