#include <actions.h>
#include <auth.h>
#include <logger.h>
#include <version.h>
#include <exceptions.h>
#include <wait.h>

using namespace doas;
using doas::permissions::Permissions;
using doas::permissions::User;
using doas::optargs::OptArgs;

#define PATH_EDIT_LOCK PATH_VAR_RUN "/doas/edit.lock"

void doas::ShowPermissions(permissions::Permissions &permissions) {
  if (permissions.Privileged()) {
    permissions.Reload(false);
  }

  for (const permissions::Entity &e : permissions) {
    std::cout << e << std::endl;
  }
}

const permissions::Entity *doas::Permit(const Permissions &perms, const OptArgs &opts) {
  char *const *cmdargv{opts.CommandArguments()};
  auto perm = perms.Get(opts.AsUser(), cmdargv);
  if (perm == nullptr || perm->Deny()) {
    std::stringstream ss;
    throw doas::PermissionError("You are not allowed to execute '%s' as %s",
                                utils::CommandArgsText(cmdargv).c_str(),
                                opts.AsUser().Name().c_str());
  }

  if (perm->PromptForPassword()) {
    if (!auth::Authenticate(perms.PamService(), perm->CacheAuth(), opts.Interactive())) {
      throw doas::PermissionError("Incorrect password");
    }
  }
  return perm;
}

void doas::DoAs(const User &user, char *const cmdargv[], char *const envp[]) {
  // update the HOME env according to the as_user dir
  setenv("HOME", user.HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  permissions::Set(user);

  // execute with uid and gid. path lookup is done internally, so execvp is not needed.
  execvpe(cmdargv[0], &cmdargv[0], envp);

  // will not get here unless execvp failed
  throw std::runtime_error(utils::CommandArgsText(cmdargv) + " : " + std::strerror(errno));
}

void doas::TurnOnVerboseOutput(const permissions::Permissions &permissions) {
  if (!permissions.Privileged()) {
    throw doas::PermissionError("Access denied. You are not allowed to view verbose output.");
  }
  logger::debug().VerboseOn();
  logger::info().VerboseOn();
  logger::warning().VerboseOn();
  logger::error().VerboseOn();
}

void doas::ClearAuthTokens(const Permissions &permissions) {
  int cleared = auth::ClearTokens(permissions.PamService());
  if (cleared < 0) {
    throw std::runtime_error("error while clearing tokens");
  }
  logger::info() << "cleared " << cleared << " tokens" << std::endl;
}

void doas::ShowVersion() {
  std::cout << "doas: " << VERSION << std::endl;
}

void doas::EditConfiguration(const OptArgs &opts, const Permissions &permissions) {

  if (!permissions.Privileged()) {
    throw doas::PermissionError("Access denied. You are not allowed to edit the config file");
  }

  if (utils::path::Exists(PATH_EDIT_LOCK)) {
    auto prompt = "doas.conf is already being edited from another session, do you want to continue anyway?";
    if (!utils::AskQuestion(prompt)) {
      throw doas::PermissionError("doas.conf is being edited from another session");
    }
    if (remove(PATH_EDIT_LOCK) != 0) {
      throw doas::IOError("%s: %s", PATH_EDIT_LOCK, std::strerror(errno));
    }
  }

  if (!auth::Authenticate(permissions.PamService(), true, true)) {
    throw doas::PermissionError("Incorrect password");
  }

  utils::path::Touch(PATH_EDIT_LOCK);
  Permissions::SecureFile(PATH_EDIT_LOCK);

  std::string tmpconf{"/tmp/doas.tmp"};
  utils::path::Touch(tmpconf);
  Permissions::SecureFile(tmpconf);

  DEFER({
          if (remove(PATH_EDIT_LOCK) != 0) {
            throw doas::IOError("%s: %s", PATH_EDIT_LOCK, std::strerror(errno));
          }

          if (utils::path::Exists(tmpconf) &&
              remove(tmpconf.c_str()) != 0) {
            throw doas::IOError("%s: %s", tmpconf.c_str(), std::strerror(errno));
          }
        });

  utils::path::Copy(PATH_CONFIG, tmpconf);

  std::vector<char *> cmdargv{
      strdup(utils::GetEditor().c_str()),
      strdup(tmpconf.c_str()),
      nullptr
  };

  // loop until configuration is valid
  // or user asked to stop
  while (true) {
    pid_t pid = fork();

    if (pid == -1) {
      throw std::runtime_error("fork() error when editing configuration");
    }

    // child process should run the editor
    if (pid == 0) {
      doas::DoAs(User{0}, cmdargv.data(), doas::env::Raw());
    }

    // parent process should wait until the child exists
    int status;
    while (-1 == waitpid(pid, &status, 0));
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

    std::string prompt{utils::StringFormat("%s is invalid. Do you want to try again?",
                                           PATH_CONFIG)};
    if (!utils::AskQuestion(prompt)) {
      std::cout << PATH_CONFIG << " changes discarded." << std::endl;
      return;
    }
  }
}

void doas::CheckConfiguration(const OptArgs &opts) {
  if (opts.CommandArguments() == nullptr) {
    if (!Permissions::Validate(opts.ConfigPath(), opts.AuthService())) {
      throw doas::ConfigError("configuration is not valid");
    }

    if (!Permissions::IsFileSecure(opts.ConfigPath())) {
      throw doas::ConfigError("configuration is not valid");
    }
  }
  Permissions perms{opts.ConfigPath(), opts.AuthService()};

  auto perm = perms.Get(opts.AsUser(), opts.CommandArguments());
  if (perm == nullptr || perm->Deny()) {
    std::cout << "deny" << std::endl;
    return;
  }
  std::cout << "permit" << (!perm->PromptForPassword() ? " nopass" : "") << std::endl;
}
