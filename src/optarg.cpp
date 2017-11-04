#include <auth.h>
#include <conf.h>
#include <exceptions.h>
#include <logger.h>
#include <version.h>
#include <gsl/gsl>

using suex::optargs::OptArgs;

OptArgs::OptArgs(int argc, char *argv[]) {
  int optind = OptArgs::ParseOpts(argc, argv);
  if (optind == argc) {
    return;
  }
  args_ = std::vector<char *>{argv + optind, argv + argc};
  // low level c code needs an indication when an array of pointers ends
  args_.emplace_back(static_cast<char *>(nullptr));
  binary_ = suex::utils::path::Locate(args_.front());
  args_.front() = utils::ConstCorrect(binary_.c_str());
}

int OptArgs::GetArgumentCount(int argc, char *argv[]) {
  std::vector<std::string> param_opts{"-C", "-a", "-u"};

  auto sp = gsl::make_span(argv, argc).subspan(1);
  std::string prevopt{};
  int counter = 1;
  for (std::string opt : sp) {
    counter++;
    prevopt = opt;
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
  if (counter != argc) {
    return counter + 1;
  }

  return counter;
}

int OptArgs::ParseOpts(int argc, char *argv[]) {
  int c;
  argc = GetArgumentCount(argc, argv);
  while (true) {
    c = getopt(argc, argv, "a:C:EVlvznsu:");
    if (c == -1) {
      return optind;
    }
    /* Detect the end of the options. */
    switch (c) {
      case 'a': {
        auth_style_ = optarg;
        break;
      }
      case 'l': {
        list_ = true;
        break;
      }
      case 'z': {
        clear_ = true;
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
        args_ =
            std::vector<char *>{utils::ConstCorrect(shell.c_str()), nullptr};
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
        config_path_ = suex::utils::path::Locate(optarg);
        break;
      }
      default: {
        // getopt will write the error, thus not need to do anything here
        throw suex::InvalidUsage();
      }
    }
  }
}
