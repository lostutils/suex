#include <actions.h>
#include <auth.h>
#include <exceptions.h>
#include <fcntl.h>
#include <file.h>
#include <logger.h>
#include <version.h>
#include <wait.h>
#include <cstring>
#include <sstream>

using suex::permissions::Permissions;
using suex::permissions::User;
using suex::optargs::OptArgs;

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
    std::stringstream ss;
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

void suex::SwitchUserAndExecute(const User &user, char *const cmdargv[],
                                char *const envp[]) {
  // update the HOME env according to the as_user dir
  setenv("HOME", user.HomeDirectory().c_str(), 1);

  // set permissions to requested id and gid
  permissions::Set(user);

  // execute with uid and gid. path lookup is done internally, so execvp is not
  // needed.
  execvpe(*cmdargv, &(*cmdargv), envp);
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

  int edit_fd = file::Open(PATH_EDIT_LOCK, O_CREAT | O_RDWR);
  DEFER({
    file::Close(edit_fd);
    file::Remove(PATH_EDIT_LOCK);
  });

  struct flock edit_lock = {0};
  if (fcntl(edit_fd, F_OFD_GETLK, &edit_lock) < 0) {
    throw suex::IOError("Error when getting edit lock configuration: %s",
                        strerror(errno));
  }

  if (edit_lock.l_type != F_UNLCK) {
    throw suex::PermissionError(
        "Configuration is being edited in another session");
  }

  edit_lock.l_type = F_WRLCK;
  if (fcntl(edit_fd, F_OFD_SETLKW, &edit_lock) < 0) {
    throw suex::IOError("Error when locking configuration: %s",
                        strerror(errno));
  }

  DEFER({
    edit_lock.l_type = F_UNLCK;
    fcntl(edit_fd, F_OFD_SETLKW, &edit_lock);
  });

  int conf_fd = file::Open(PATH_CONFIG, O_RDWR);
  DEFER(file::Close(conf_fd));

  int tmp_fd =
      file::Open(PATH_TMP, O_TMPFILE | O_RDWR | O_EXCL, S_IRUSR | S_IRGRP);
  DEFER(file::Close(tmp_fd));

  // secure the file
  // -> copy the content
  // -> make it rw by root:root
  file::Clone(conf_fd, tmp_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
  std::string tmp_path{utils::path::GetPath(tmp_fd)};
  std::string editor{utils::GetEditor()};
  std::vector<char *> cmdargv{utils::ConstCorrect(editor.c_str()),
                              utils::ConstCorrect(tmp_path.c_str()), nullptr};

  while (true) {
    pid_t pid = fork();

    if (pid == -1) {
      throw std::runtime_error("fork() error when editing configuration");
    }

    // child process should run the editor
    if (pid == 0) {
      suex::SwitchUserAndExecute(RootUser(), cmdargv.data(), suex::env::Raw());
    }

    // parent process should wait until the child exists
    int status;
    while (-1 == waitpid(pid, &status, 0)) {
    };
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      throw std::runtime_error("error while waiting for $EDITOR");
    }

    if (Permissions::Validate(tmp_fd, opts.AuthStyle())) {
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
  if (fcntl(conf_fd, F_OFD_SETLKW, &write_lock) < 0) {
    throw suex::IOError("Error when locking configuration: %s",
                        strerror(errno));
  }

  DEFER({
    write_lock.l_type = F_UNLCK;
    fcntl(conf_fd, F_OFD_SETLKW, &write_lock);
  });

  file::Clone(tmp_fd, conf_fd, S_IRUSR | S_IRGRP);
  std::cout << PATH_CONFIG << " changes applied." << std::endl;
}

void suex::CheckConfiguration(const OptArgs &opts) {
  if (opts.CommandArguments().empty()) {
    int fd = file::Open(opts.ConfigPath(), O_RDONLY);
    if (!Permissions::Validate(fd, opts.AuthStyle())) {
      throw suex::ConfigError("configuration is not valid");
    }

    // done here...
    return;
  }

  Permissions perms{opts.ConfigPath(), opts.AuthStyle()};

  auto perm = perms.Get(opts.AsUser(), opts.CommandArguments());
  if (perm == nullptr || perm->Deny()) {
    std::cout << "deny" << std::endl;
    return;
  }
  std::cout << "permit" << (!perm->PromptForPassword() ? " nopass" : "")
            << std::endl;
}
