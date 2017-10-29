#include <auth.h>
#include <conf.h>
#include <exceptions.h>
#include <logger.h>
#include <version.h>

using namespace suex;
using namespace suex::utils;
using namespace suex::optargs;

OptArgs::OptArgs(int argc, char *argv[]) {
  int optind = ParseOpts(argc, argv);
  if (optind == argc) {
    return;
  }
  args_ = std::vector<char *>{argv + optind, argv + argc};
  // low level c code needs an indication when an array of pointers ends
  args_.emplace_back((char *) nullptr);
  binary_ = path::Locate(args_.front());
  args_.front() = (char *) binary_.c_str();
}

int OptArgs::GetArgumentCount(int argc, char *argv[]) {
  std::vector<std::string> param_opts{"-C", "-a", "-u"};
  std::string prevopt, opt;
  int i;
  for (i = 1; i < argc; i++) {
    prevopt = opt;
    opt = argv[i];
    if (opt.front() == '-') {
      continue;
    }

    if (std::find(param_opts.begin(), param_opts.end(), prevopt) !=
        param_opts.end()) {
      continue;
    }

    break;
  }

  // need to start from next index
  if (i != argc) {
    return i + 1;
  }

  return i;
}
int OptArgs::ParseOpts(int argc, char *argv[]) {
  int c;
  argc = GetArgumentCount(argc, argv);
  while (true) {
    c = getopt(argc, argv, "a:C:EVDvLnsu:");
    if (c == -1) {
      return optind;
    }
    /* Detect the end of the options. */
    switch (c) {
      case 'a': {
        pam_service_ = optarg;
        break;
      }
      case 'D': {
        show_perms_ = true;
        break;
      }
      case 'L': {
        clear_auth_tokens_ = true;
        break;
      }
      case 'n': {
        interactive_ = false;
        break;
      }
      case 's': {
        std::string shell{running_user.Shell()};
        if (env::Contains("SHELL")) {
          shell = env::Get("SHELL");
        }
        args_ = std::vector<char *>{strdup(shell.c_str()), nullptr};
        break;
      }
      case 'E': {
        edit_config_ = true;
        break;
      }
      case 'V': {
        verbose_mode_ = true;
        break;
      }
      case 'v': {
        show_version_ = true;
        break;
      }
      case 'u': {
        // extract the username and group
        user_ = permissions::User(optarg);
        if (!user_.Exists()) {
          throw suex::PermissionError("user '%s' doesn't exist", optarg);
        }
        break;
      }
      case 'C': {
        config_path_ = path::Locate(optarg);
        break;
      }
      default: {
        // getopt will write the error, thus not need to do anything here
        throw suex::InvalidUsage();
      }
    }
  }
}
