#include <actions.h>
#include <auth.h>
#include <exceptions.h>
#include <logger.h>
#include <version.h>

using namespace suex;
using namespace suex::utils;
using namespace suex::optargs;
using namespace suex::env;
using namespace suex::permissions;

void ShowUsage() {
  std::cout << "usage: suex [-LEVDvns] [-a style] [-C config] [-u user] "
               "command [args]"
            << std::endl;
}

void CreateRunDirectory() {
  struct stat fstat {};
  if (stat(PATH_VAR_RUN, &fstat) != 0) {
    throw suex::IOError(std::strerror(errno));
  }

  // create the directory
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

char *const *GetEnv(std::vector<char *> &vec, const Permissions &permissions,
                    const OptArgs &opts) {
  char *const *envp = env::Raw();
  if (utils::BypassPermissions(opts.AsUser())) {
    return envp;
  }

  auto perm = Permit(permissions, opts);
  if (!perm->KeepEnvironment()) {
    envp = new char *[9]{
        env::GetRaw("DISPLAY"), env::GetRaw("HOME"),     env::GetRaw("LOGNAME"),
        env::GetRaw("MAIL"),    env::GetRaw("PATH"),     env::GetRaw("TERM"),
        env::GetRaw("USER"),    env::GetRaw("USERNAME"), nullptr};
  }

  if (!perm->EnvironmentVariablesConfigured()) {
    return envp;
  }

  for (int i = 0; envp[i] != nullptr; i++) {
    auto ev = env::SplitRaw(envp[i]);

    if (perm->ShouldRemoveEnvVar(ev.first)) {
      continue;
    }

    if (perm->ShouldAddEnvVar(ev.first)) {
      continue;
    }

    vec.emplace_back(env::ToRaw(ev.first, ev.second));
  }

  for (const auto &ev : perm->EnvVarsToAdd()) {
    vec.emplace_back(env::ToRaw(ev.first, ev.second));
  }

  vec.emplace_back(nullptr);

  return vec.data();
}

int Do(Permissions &permissions, const OptArgs &opts) {
  if (opts.VerboseMode()) {
    TurnOnVerboseOutput(permissions);
  }

  if (opts.EditConfig()) {
    EditConfiguration(opts, permissions);
    return 0;
  }

  // up to here, we don't check if the file is valid
  // because the edit config command can edit invalid files
  if ((!permissions.Size()) > 0) {
    throw suex::PermissionError(
        "suex.conf is either invalid or empty.\n! notice that you're not a "
        "member of 'wheel'");
  }

  if (opts.ShowPermissions()) {
    ShowPermissions(permissions);
    return 0;
  }

  if (opts.ShowVersion()) {
    ShowVersion();
    return 0;
  }

  if (opts.ClearAuthTokens()) {
    ClearAuthTokens(permissions);
    return 0;
  }

  if (opts.CommandArguments() == nullptr) {
    ShowUsage();
    return 1;
  }

  if (!opts.ConfigPath().empty()) {
    CheckConfiguration(opts);
    return 0;
  }

  std::vector<char *> envs;

  SwitchUserAndExecute(opts.AsUser(), opts.CommandArguments(),
                       GetEnv(envs, permissions, opts));
  return 0;
}

int main(int argc, char *argv[]) {
  try {
    ValidateBinaryOwnership(*argv);
    CreateRunDirectory();

    OptArgs opts{argc, argv};
    Permissions permissions{PATH_CONFIG, opts.AuthService()};

    return Do(permissions, opts);
  } catch (InvalidUsage &) {
    ShowUsage();
    return 1;
  } catch (SuExError &e) {
    std::cerr << e.what() << std::endl;

    return 1;
  }
}
