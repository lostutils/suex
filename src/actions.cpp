#include <actions.h>
#include <auth.h>
#include <exceptions.h>
#include <fcntl.h>
#include <file.h>
#include <fmt.h>
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
  int cleared = auth::ClearTokens(permissions.AuthStyle());
  if (cleared < 0) {
    throw std::runtime_error("error while clearing tokens");
  }
  logger::info() << "cleared " << cleared << " tokens" << std::endl;
}

void suex::ShowVersion() { std::cout << "suex: " << VERSION << std::endl; }

const re2::RE2 &fdre() {
  static const re2::RE2 re{R"(^(.*)\s+\(deleted\)$)"};
  if (!re.ok()) {
    throw std::runtime_error("comment regex failed to compile");
  }
  return re;
}

void suex::EditConfiguration(const OptArgs &opts,
                             const Permissions &permissions) {
  int src_fd = open(PATH_CONFIG, O_RDWR, 0);

  if (src_fd == -1) {
    throw suex::IOError(std::strerror(errno));
  }

  DEFER(close(src_fd));

  struct flock lock = {0};
  lock.l_type = F_WRLCK;

  if (fcntl(src_fd, F_OFD_SETLK, &lock) < 0) {
    if (errno & (EACCES | EAGAIN)) {
      throw suex::PermissionError(
          "Configuration is being edited in another session");
    }
    throw suex::IOError(
        Sprintf("Error when locking configuration: %s", strerror(errno)));
  }

  DEFER({
    lock.l_type = F_UNLCK;
    fcntl(src_fd, F_OFD_SETLKW, &lock);
  });

  if (!permissions.Privileged()) {
    throw suex::PermissionError(
        "Access denied. You are not allowed to edit the config file");
  }

  if (!auth::Authenticate(permissions.AuthStyle(), true)) {
    throw suex::PermissionError("Incorrect password");
  }

  FILE *tmp_f = tmpfile();
  if (tmp_f == nullptr) {
    throw suex::IOError("Couldn't create a temporary configuration file");
  }
  DEFER(fclose(tmp_f));

  int dst_fd{fileno(tmp_f)};

  std::string tmp_conf{Sprintf("/proc/%d/fd/%d", getpid(), dst_fd)};

  // secure the file
  // -> copy the content
  // -> make it rw by root:root
  file::Clone(src_fd, dst_fd, true);

  if (fchmod(dst_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0) {
    throw suex::PermissionError(std::strerror(errno));
  }

  std::string editor{utils::GetEditor()};
  std::vector<char *> cmdargv{utils::ConstCorrect(editor.c_str()),
                              utils::ConstCorrect(tmp_conf.c_str()), nullptr};

  // loop until configuration is valid or user asked to stop
  // also turn on verbose output when editing
  TurnOnVerboseOutput(permissions);
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

    // we can't secure files that have write permissions
    if (fchmod(dst_fd, S_IRUSR | S_IRGRP) < 0) {
      throw suex::PermissionError(std::strerror(errno));
    }

    // update the file permissions after editing it
    if (Permissions::Validate(tmp_conf, opts.AuthStyle())) {
      file::Clone(dst_fd, src_fd, true);
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
    if (!Permissions::Validate(opts.ConfigPath(), opts.AuthStyle())) {
      throw suex::ConfigError("configuration is not valid");
    }

    if (opts.ConfigPath() == PATH_CONFIG &&
        !file::IsSecure(opts.ConfigPath())) {
      throw suex::ConfigError("configuration file is not secure");
    }

    // done here
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
