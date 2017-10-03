#include <conf.h>
#include <logger.h>
#include <options.h>
#include <version.h>
#include <env.h>
#include <auth.h>

int Do(const Permissions &permissions, const Options &opts, const Environment &env) {

  char *const *cmdargv{opts.CommandArguments()};
  std::string cmd_txt{CommandArgsText(cmdargv)};
  char *const *envp = env.Raw();

  if (!BypassPermissions(opts.AsUser())) {
    auto perm = permissions.Get(opts.AsUser(), cmdargv);
    if (perm == nullptr || perm->Deny()) {
      std::stringstream ss;
      ss << "You can't execute '" << cmd_txt <<
         "' as " << opts.AsUser().Name()
         << ": " << std::strerror(EPERM);
      throw std::runtime_error(ss.str());
    }

    if (perm->PromptForPassword()) {
      bool authenticated = false;
      int attempts{3};
      for (int i = 0; i < attempts && !authenticated; ++i) {
        authenticated = Authenticate("common-auth");
        if (!authenticated) {
          std::cerr << "Sorry, try again." << std::endl;
        }
      }
      if (!authenticated) {
        std::stringstream ss;
        ss << attempts << " incorrect password attempts" << std::endl;
        throw std::runtime_error(ss.str());

      }

      if (!perm->KeepEnvironment()) {
        envp = {nullptr};
      }
    }
  }
  // update the HOME env according to the as_user dir
  setenv("HOME", opts.AsUser().HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  SetPermissions(opts.AsUser());

  // execute with uid and gid. path lookup is done internally, so execvp is not needed.
  execvpe(cmdargv[0], &cmdargv[0], envp);

  // will not get here unless execvp failed
  throw std::runtime_error(cmd_txt + " : " + std::strerror(errno));
}

int main(int argc, char *argv[], char *envp[]) {
  try {
    // check that enough args were passed
    if (argc < 2) {
      std::cout << "Usage: " << argv[0]
                << " user-spec command [args]" << std::endl << std::endl <<
                "version: " << VERSION << ", license: MIT" << std::endl;
      return 0;
    }

    // check that enough args were passed
    // check that the running binary has the right permissions
    // i.e: suid is set and owned by root:root
    //ValidateBinary(GetPath(*argv, true));

    // load the arguments into a vector, then add a null at the end,
    // to have an indication when the vector ends
    Options opts{argc, argv};

    // load the configuration from the default path
    Permissions permissions{opts.ConfigurationPath()};

    // load all the environment variables
    Environment env{envp};

    return Do(permissions, opts, env);

  } catch (std::exception &e) {
    logger::error << e.what() << std::endl;
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
