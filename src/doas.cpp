#include <conf.h>
#include <logger.h>
#include <options.h>
#include <version.h>
#include <env.h>
#include <auth.h>

const ExecutablePermissions *Permit(const Permissions &permissions, const Options &opts) {
  char *const *cmdargv{opts.CommandArguments()};
  auto perm = permissions.Get(opts.AsUser(), cmdargv);
  if (perm == nullptr || perm->Deny()) {
    std::cerr << "You can't execute '" << CommandArgsText(cmdargv) <<
              "' as " << opts.AsUser().Name();
    return nullptr;
  }

  if (perm->PromptForPassword()) {
    if (Authenticate(opts.AuthenticationService(), perm->CacheAuth())) {
      std::cerr << "Incorrect password" << std::endl;
      return nullptr;
    }
  }
  return perm;
}
int DoAs(const User &user, char * const cmdargv[], char *const envp[]) {
  // update the HOME env according to the as_user dir
  setenv("HOME", user.HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  SetPermissions(user);

  // execute with uid and gid. path lookup is done internally, so execvp is not needed.
  execvpe(cmdargv[0], &cmdargv[0], envp);

  // will not get here unless execvp failed
  throw std::runtime_error(CommandArgsText(cmdargv) + " : " + std::strerror(errno));
}

int Do(const Permissions &permissions, const Options &opts, const Environment &env) {
  char *const *envp = env.Raw();
  if (!BypassPermissions(opts.AsUser())) {
    auto perm = Permit(permissions, opts);
    if (perm == nullptr) {
      return 1;
    }

    if (!perm->KeepEnvironment()) {
      envp = {nullptr};
    }
  }
  return DoAs(opts.AsUser(), opts.CommandArguments(), envp);
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
