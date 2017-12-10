#include <actions.h>
#include <auth.h>
#include <exceptions.h>
#include <logger.h>
#include <version.h>
#include <gsl/gsl>

#define BACKWARD_HAS_DW 1
#include "backward-cpp/backward.hpp"

using suex::optargs::OptArgs;
using suex::permissions::Permissions;

void ShowUsage() {
  std::cout << "usage: suex [-LEVzvns] [-a style] [-C config] [-u user] "
               "command [args]"
            << std::endl;
}

void CreateRuntimeDirectories() {
  struct stat fstat {};
  if (stat(PATH_VAR_RUN, &fstat) != 0) {
    throw suex::IOError(std::strerror(errno));
  }

  if (stat(PATH_SUEX_TMP, &fstat) != 0) {
    if (mkdir(PATH_SUEX_TMP, S_IRUSR | S_IRGRP) < 0) {
      throw suex::IOError(std::strerror(errno));
    }

    if (chown(PATH_SUEX_TMP, 0, 0) < 0) {
      throw suex::PermissionError(std::strerror(errno));
    }

    if (stat(PATH_SUEX_TMP, &fstat) != 0) {
      throw suex::IOError(std::strerror(errno));
    }
  }

  if (!S_ISDIR(fstat.st_mode)) {
    throw suex::IOError("auth timestamp directory is not a directory");
  }
}

char *const *GetEnv(std::vector<char *> *vec, const permissions::Entity &entity,
                    char *environ[]) {
  if (!entity.EnvironmentVariablesConfigured()) {
    return environ;
  }

  for (int i = 0; environ[i] != nullptr; i++) {
    auto ev = env::SplitRaw(environ[i]);

    if (entity.ShouldRemoveEnvVar(ev.first)) {
      continue;
    }

    if (entity.ShouldAddEnvVar(ev.first)) {
      continue;
    }

    vec->emplace_back(env::ToRaw(ev.first, ev.second));
  }

  for (const auto &ev : entity.EnvVarsToAdd()) {
    vec->emplace_back(env::ToRaw(ev.first, ev.second));
  }

  vec->emplace_back(nullptr);

  return vec->data();
}

char *const *GetEnv(std::vector<char *> *vec, const Permissions &permissions,
                    const OptArgs &opts) {
  auto envp = env::Raw();

  if (utils::BypassPermissions(opts.AsUser())) {
    return envp;
  }
  auto perm = Permit(permissions, opts);
  if (!perm->KeepEnvironment()) {
    // NOT deleting since environment is global and should exist
    // as long as the app is running
    envp = new char *[9]{
        env::GetRaw("DISPLAY"), env::GetRaw("HOME"),     env::GetRaw("LOGNAME"),
        env::GetRaw("MAIL"),    env::GetRaw("PATH"),     env::GetRaw("TERM"),
        env::GetRaw("USER"),    env::GetRaw("USERNAME"), nullptr};
  }

  return GetEnv(vec, *perm, envp);
}

int Do(const Permissions &permissions, const OptArgs &opts) {
  CreateRuntimeDirectories();

  if (opts.VerboseMode()) {
    TurnOnVerboseOutput(permissions);
  }

  if (opts.EditConfig()) {
    if (opts.Clear()) {
      RemoveEditLock();
    }

    EditConfiguration(opts, permissions);
    return 0;
  }

  // up to here, we don't check if the file is valid
  // because the edit config command can edit invalid files
  if (permissions.Size() <= 0) {
    throw suex::PermissionError(
        "suex.conf is either invalid or empty.\n! notice that you're not a "
        "member of 'wheel'");
  }

  if (opts.ListPermissions()) {
    ShowPermissions(permissions);
    return 0;
  }

  if (opts.ShowVersion()) {
    ShowVersion();
    return 0;
  }

  if (opts.Clear()) {
    ClearAuthTokens(permissions);
    return 0;
  }

  if (!opts.ConfigPath().empty()) {
    CheckConfiguration(opts);
    return 0;
  }

  if (opts.CommandArguments().empty()) {
    ShowUsage();
    return 1;
  }

  std::vector<char *> envs;

  SwitchUserAndExecute(opts.AsUser(), opts.CommandArguments().data(),
                       GetEnv(&envs, permissions, opts));
  return 0;
}

int main(int argc, char *argv[]) {
  try {
    if (static_cast<int>(geteuid()) != RootUser().Id() ||
        static_cast<int>(getegid()) != RootUser().GroupId()) {
      throw suex::PermissionError("suex setid & setgid are no set", geteuid(),
                                  getegid());
    }
    OptArgs opts{argc, argv};
    Permissions permissions{PATH_CONFIG, opts.AuthStyle(),
                            opts.ListPermissions()};
    return Do(permissions, opts);
  } catch (InvalidUsage &) {
    ShowUsage();
    return 1;
  } catch (SuExError &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  }
}
