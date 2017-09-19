#include <sstream>
#include <path.h>
#include <cstring>
#include <optarg.h>
#include <fstream>
#include <logger.h>
#include <auth.h>
#include <version.h>
#include <conf.h>
#include <exceptions.h>

using namespace doas;
using namespace doas::utils;
using namespace doas::optargs;

OptArgs::OptArgs(int argc, char *argv[]) {
  int app_argc = ParseOpts(argc, argv);
  if (app_argc == argc) {
    return;
  }
  args_ = std::vector<char *> {argv + app_argc, argv + argc};
  // low level c code needs an indication when an array of pointers ends
  args_.emplace_back((char *) nullptr);
  binary_ = path::Locate(args_.front());
  args_.front() = (char *) binary_.c_str();
}

int OptArgs::ParseOpts(int argc, char **argv) {
  int app_argc, c;

  for (app_argc = 1; app_argc < argc; ++app_argc) {
    if (argv[app_argc][0] != '-') {
      break;
    }
  }

  // need to start from next index
  if (app_argc != argc) {
    app_argc++;
  }
  while (true) {
    c = getopt(app_argc, argv, "u:a:C:LEVDvns");
    /* Detect the end of the options. */
    switch (c) {
      case -1: {
        return optind;
      }
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
        args_ = std::vector<char *> {
            strdup(shell.c_str()),
            nullptr
        };
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
          throw doas::PermissionError("user '%s' doesn't exist", optarg);
        }
        break;
      }
      case 'C': {
        config_path_ = path::Locate(optarg);
        break;
      }
      default: {
        // getopt will write the error, thus not need to do anything here
        throw doas::DoAsError("");
      }
    }
  }
}

