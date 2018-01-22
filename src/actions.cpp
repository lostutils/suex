#include <wait.h>
#include <actions.hpp>
#include <auth.hpp>
#include <logger.hpp>
#include <sstream>
#include <version.hpp>

using suex::optargs::OptArgs;
using suex::permissions::Permissions;
using suex::permissions::User;

#define PATH_EDIT_LOCK PATH_VAR_RUN "/suex/edit.lock"

void suex::ShowPermissions(const permissions::Permissions &permissions) {
  for (const permissions::Entity &e : permissions) {
    if (e.Owner().Id() != RunningUser().Id() && !permissions.Privileged()) {
      continue;
    }

    std::cout << e << std::endl;
  }
}

const permissions::Entity *suex::Permit(const Permissions &permissions,
                                        const OptArgs &opts) {
  auto perm = permissions.Get(opts.AsUser(), opts.CommandArguments());
  if (perm == nullptr || perm->Deny()) {
    std::ostringstream ss;
    throw suex::PermissionError(
        "You are not allowed to execute '%s' as %s",
        utils::CommandArgsText(opts.CommandArguments()).c_str(),
        opts.AsUser().Name().c_str());
  }

  if (perm->PromptForPassword()) {
    std::string cache_token{perm->CacheAuth() ? perm->Command() : ""};
    if (!auth::Authenticate(permissions.AuthStyle(), opts.Interactive(),
                            cache_token)) {
      throw suex::PermissionError("Incorrect password");
    }
  }
  return perm;
}

void suex::SwitchUserAndExecute(const User &user,
                                const std::vector<char *> &cmdargv,
                                char *const envp[]) {
  // update the HOME env according to the as_user dir
  setenv("HOME", user.HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  permissions::Set(user);

  // execute with uid and gid. path lookup is done internally, so execvp is not
  // needed.

  logger::debug() << "executing: " << utils::CommandArgsText(cmdargv)
                  << std::endl;

  execvpe(*cmdargv.data(), &(*cmdargv.data()), envp);
}

void suex::TurnOnVerboseOutput() {
  if (!Permissions::Privileged()) {
    throw suex::PermissionError(
        "Access denied. You are not allowed to view verbose output.");
  }
  logger::debug().VerboseOn();
  logger::info().VerboseOn();
  logger::warning().VerboseOn();
  logger::error().VerboseOn();
}

void suex::ClearAuthTokens(const Permissions &permissions) {
  int cleared = auth::ClearTokens(permissions.AuthStyle());
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

  if (!auth::Authenticate(permissions.AuthStyle(), true)) {
    throw suex::PermissionError("Incorrect password");
  }

  file::File edit_f{PATH_EDIT_LOCK, O_CREAT | O_RDWR};

  DEFER({ edit_f.Remove(); });

  struct flock edit_lock = {0};
  edit_lock.l_type = F_WRLCK;
  if (edit_f.Control(F_OFD_SETLK, &edit_lock) < 0) {
    if (errno == EAGAIN || errno == EACCES) {
      throw suex::ConfigError(
          "Configuration is being edited in another session");
    }
    throw suex::IOError("error when locking configuration: %s",
                        strerror(errno));
  }

  DEFER({
    edit_lock.l_type = F_UNLCK;
    if (edit_f.Control(F_OFD_SETLKW, &edit_lock) < 0) {
      throw suex::IOError("error when unlocking configuration: %s",
                          strerror(errno));
    }
  });

  file::File conf_f(PATH_CONFIG, O_RDWR);
  file::File tmp_f(PATH_TMP, O_TMPFILE | O_RDWR | O_EXCL, S_IRUSR | S_IRGRP);

  conf_f.Clone(tmp_f, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  Permissions perms{tmp_f, opts.AuthStyle()};

  std::string editor{utils::GetEditor()};
  std::vector<char *> cmdargv{
      utils::ConstCorrect(editor.c_str()),
      utils::ConstCorrect(tmp_f.DescriptorPath().c_str()), nullptr};

  while (true) {
    pid_t pid = fork();

    if (pid == -1) {
      throw std::runtime_error("fork() error when editing configuration");
    }

    // child process should run the editor
    if (pid == 0) {
      suex::SwitchUserAndExecute(RootUser(), cmdargv, suex::env::Raw());
    }

    // parent process should wait until the child exists
    int status;
    while (-1 == waitpid(pid, &status, 0)) {
    };
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      throw std::runtime_error("error while waiting for $EDITOR");
    }

    if (perms.Reload().Size() > 0) {
      break;
    }

    std::string prompt{
        Sprintf("%s is invalid. Do you want to try again?", PATH_CONFIG)};
    if (!utils::AskQuestion(prompt)) {
      std::cerr << PATH_CONFIG << " changes discarded." << std::endl;
      return;
    }
  }

  struct flock write_lock = {0};
  write_lock.l_type = F_WRLCK;
  if (conf_f.Control(F_OFD_SETLKW, &write_lock) < 0) {
    throw suex::IOError("error when locking configuration: %s",
                        strerror(errno));
  }

  DEFER({
    write_lock.l_type = F_UNLCK;
    if (conf_f.Control(F_OFD_SETLKW, &write_lock) < 0) {
      throw suex::IOError("error when unlocking configuration: %s",
                          strerror(errno));
    }
  });

  tmp_f.Clone(conf_f, S_IRUSR | S_IRGRP);
  std::cout << PATH_CONFIG << " changes applied." << std::endl;
}

void suex::CheckConfiguration(const OptArgs &opts) {
  if (opts.CommandArguments().empty()) {
    file::File f{opts.ConfigPath(), O_RDONLY};
    if (Permissions(f, opts.AuthStyle()).Load().Size() <= 0) {
      throw suex::ConfigError("configuration is not valid");
    }

    // done here...
    return;
  }

  auto perms = Permissions(opts.ConfigPath(), opts.AuthStyle()).Load();
  auto perm = perms.Get(opts.AsUser(), opts.CommandArguments());
  if (perm == nullptr || perm->Deny()) {
    std::cout << "deny" << std::endl;
    return;
  }
  std::cout << "permit" << (!perm->PromptForPassword() ? " nopass" : "")
            << std::endl;
}
