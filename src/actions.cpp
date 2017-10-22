#include <actions.h>
#include <auth.h>
#include <exceptions.h>
#include <logger.h>
#include <version.h>
#include <wait.h>

using namespace suex;
using suex::permissions::Permissions;
using suex::permissions::User;
using suex::optargs::OptArgs;

#define PATH_EDIT_LOCK PATH_VAR_RUN "/suex/edit.lock"

void suex::ShowPermissions(permissions::Permissions &permissions) {
  if (permissions.Privileged()) {
    permissions.Reload(false);
  }

  for (const permissions::Entity &e : permissions) {
    std::cout << e << std::endl;
  }
}

const permissions::Entity *suex::Permit(const Permissions &perms,
                                        const OptArgs &opts) {
  char *const *cmdargv{opts.CommandArguments()};
  auto perm = perms.Get(opts.AsUser(), cmdargv);
  if (perm == nullptr || perm->Deny()) {
    std::stringstream ss;
    throw suex::PermissionError("You are not allowed to execute '%s' as %s",
                                utils::CommandArgsText(cmdargv).c_str(),
                                opts.AsUser().Name().c_str());
  }

  if (perm->PromptForPassword()) {
    std::string cache_token{perm->CacheAuth() ? perm->Command() : ""};
    if (!auth::Authenticate(perms.AuthService(), opts.Interactive(),
                            cache_token)) {
      throw suex::PermissionError("Incorrect password");
    }
  }
  return perm;
}

void suex::SwitchUserAndExecute(const User &user, char *const *cmdargv, char *const *envp) {
  // update the HOME env according to the as_user dir
  setenv("HOME", user.HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  permissions::Set(user);

  // execute with uid and gid. path lookup is done internally, so execvp is not
  // needed.
  execvpe(cmdargv[0], &cmdargv[0], envp);

  // will not get here unless execvp failed
  throw std::runtime_error(utils::CommandArgsText(cmdargv) + " : " +
                           std::strerror(errno));
}

void suex::TurnOnVerboseOutput(const permissions::Permissions &permissions) {
  if (!permissions.Privileged()) {
    throw suex::PermissionError(
        "Access denied. You are not allowed to view verbose output.");
  }
  logger::debug().VerboseOn();
  logger::info().VerboseOn();
  logger::warning().VerboseOn();
  logger::error().VerboseOn();
}

void suex::ClearAuthTokens(const Permissions &permissions) {
  int cleared = auth::ClearTokens(permissions.AuthService());
  if (cleared < 0) {
    throw std::runtime_error("error while clearing tokens");
  }
  logger::info() << "cleared " << cleared << " tokens" << std::endl;
}

void suex::ShowVersion() { std::cout << "suex: " << VERSION << std::endl; }

void suex::EditConfiguration(const OptArgs &opts,
                             const Permissions &permissions) {
  if (!permissions.Privileged()) {
    throw suex::PermissionError(
        "Access denied. You are not allowed to edit the config file");
  }

  // verbose is needed when editing
  TurnOnVerboseOutput(permissions);

  if (utils::path::Exists(PATH_EDIT_LOCK)) {
    auto prompt =
        "suex.conf is already being edited from another session, do you want "
        "to continue anyway?";
    if (!utils::AskQuestion(prompt)) {
      throw suex::PermissionError(
          "suex.conf is being edited from another session");
    }
    if (remove(PATH_EDIT_LOCK) != 0) {
      throw suex::IOError("%s: %s", PATH_EDIT_LOCK, std::strerror(errno));
    }
  }

  if (!auth::Authenticate(permissions.AuthService(), true)) {
    throw suex::PermissionError("Incorrect password");
  }

  utils::path::Touch(PATH_EDIT_LOCK);
  Permissions::SecureFile(PATH_EDIT_LOCK);

  std::string tmpconf{"/tmp/suex.tmp"};
  utils::path::Touch(tmpconf);
  Permissions::SecureFile(tmpconf);

  DEFER({
    if (remove(PATH_EDIT_LOCK) != 0) {
      throw suex::IOError("%s: %s", PATH_EDIT_LOCK, std::strerror(errno));
    }

    if (utils::path::Exists(tmpconf) && remove(tmpconf.c_str()) != 0) {
      throw suex::IOError("%s: %s", tmpconf.c_str(), std::strerror(errno));
    }
  });

  utils::path::Copy(PATH_CONFIG, tmpconf);

  std::vector<char *> cmdargv{strdup(utils::GetEditor().c_str()),
                              strdup(tmpconf.c_str()), nullptr};

  // loop until configuration is valid
  // or user asked to stop
  while (true) {
    pid_t pid = fork();

    if (pid == -1) {
      throw std::runtime_error("fork() error when editing configuration");
    }

    // child process should run the editor
    if (pid == 0) {
      suex::SwitchUserAndExecute(User{0}, cmdargv.data(), suex::env::Raw());
    }

    // parent process should wait until the child exists
    int status;
    while (-1 == waitpid(pid, &status, 0))
      ;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      throw std::runtime_error("error while waiting for $EDITOR");
    }

    // update the file permissions after editing it
    if (Permissions::Validate(tmpconf, opts.AuthService())) {
      utils::path::Move(tmpconf, PATH_CONFIG);
      Permissions::SecureFile(PATH_CONFIG);
      std::cout << PATH_CONFIG << " changes applied." << std::endl;
      return;
    }

    std::string prompt{utils::StringFormat(
        "%s is invalid. Do you want to try again?", PATH_CONFIG)};
    if (!utils::AskQuestion(prompt)) {
      std::cout << PATH_CONFIG << " changes discarded." << std::endl;
      return;
    }
  }
}

void suex::CheckConfiguration(const OptArgs &opts) {
  if (opts.CommandArguments() == nullptr) {
    if (!Permissions::Validate(opts.ConfigPath(), opts.AuthService())) {
      throw suex::ConfigError("configuration is not valid");
    }

    if (!Permissions::IsFileSecure(opts.ConfigPath())) {
      throw suex::ConfigError("configuration is not valid");
    }
  }
  Permissions perms{opts.ConfigPath(), opts.AuthService()};

  auto perm = perms.Get(opts.AsUser(), opts.CommandArguments());
  if (perm == nullptr || perm->Deny()) {
    std::cout << "deny" << std::endl;
    return;
  }
  std::cout << "permit" << (!perm->PromptForPassword() ? " nopass" : "")
            << std::endl;
}
