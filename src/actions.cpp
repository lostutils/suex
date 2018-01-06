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

  int conf_fd = open(PATH_CONFIG, O_NOFOLLOW | O_RDWR);
  if (conf_fd == -1) {
    throw suex::IOError("error opening configuration file: %s",
                        std::strerror(errno));
  }

  DEFER(close(conf_fd));

  struct flock lock = {0};

  if (fcntl(conf_fd, F_OFD_GETLK, &lock) < 0) {
    throw suex::IOError("Error when getting lock configuration: %s",
                        strerror(errno));
  }

  if (lock.l_type != F_UNLCK) {
    throw suex::PermissionError(
        "Configuration is being edited in another session");
  }

  lock.l_type = F_WRLCK;
  if (fcntl(conf_fd, F_OFD_SETLKW, &lock) < 0) {
    throw suex::IOError("Error when locking configuration: %s",
                        strerror(errno));
  }

  DEFER({
    lock.l_type = F_UNLCK;
    fcntl(conf_fd, F_OFD_SETLKW, &lock);
  });

  int tmp_fd = open(PATH_TMP, O_TMPFILE | O_RDWR | O_EXCL, S_IRUSR | S_IRGRP);
  if (tmp_fd < 0) {
    throw suex::IOError("Couldn't create a temporary configuration file: %s",
                        strerror(errno));
  }
  DEFER(close(tmp_fd));
  std::string tmp_path{utils::path::GetPath(tmp_fd)};

  // secure the file
  // -> copy the content
  // -> make it rw by root:root
  file::Clone(conf_fd, tmp_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

  std::string editor{utils::GetEditor()};
  std::vector<char *> cmdargv{utils::ConstCorrect(editor.c_str()),
                              utils::ConstCorrect(tmp_path.c_str()), nullptr};

  // loop until configuration is valid or user asked to stop
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
      // wait...
    };
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      throw std::runtime_error("error while waiting for $EDITOR");
    }

    // update the file permissions after editing it
    if (Permissions::Validate(tmp_fd, opts.AuthStyle())) {
      file::Clone(tmp_fd, conf_fd, S_IRUSR | S_IRGRP);
      std::cout << PATH_CONFIG << " changes applied." << std::endl;
      return;
    }

    std::string prompt{
        Sprintf("%s is invalid. Do you want to try again?", PATH_CONFIG)};
    if (!utils::AskQuestion(prompt)) {
      std::cout << PATH_CONFIG << " changes discarded." << std::endl;
      return;
    }
  }
}

void suex::CheckConfiguration(const OptArgs &opts) {
  if (opts.CommandArguments().empty()) {
    int fd = open(opts.ConfigPath().c_str(), O_RDONLY);
    if (fd < 0) {
      throw suex::ConfigError("couldn't open '%s' for reading: %s",
                              opts.ConfigPath().c_str(), strerror(errno));
    }

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
