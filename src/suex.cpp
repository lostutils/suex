#include <actions.hpp>
#include <auth.hpp>
#include <backward-cpp/backward.hpp>
#include <logger.hpp>
#include <version.hpp>

using suex::optargs::OptArgs;
using suex::permissions::Permissions;

void ShowUsage() {
  std::cout << "usage: suex [-LEVzvns] [-a style] [-C config] [-u user] "
               "command [args]"
            << std::endl;
}

void CreateRuntimeDirectories() {
  file::stat_t fstat{0};
  if (stat(PATH_SUEX_TMP, &fstat) != 0) {
    if (mkdir(PATH_SUEX_TMP, S_IRUSR | S_IRGRP) < 0) {
      throw suex::IOError("mkdir('%s') failed: %s", PATH_SUEX_TMP,
                          std::strerror(errno));
    }

    return CreateRuntimeDirectories();
  }

  if (fstat.st_gid != 0 || fstat.st_uid != 0) {
    if (remove(PATH_SUEX_TMP) == 0) {
      return CreateRuntimeDirectories();
    }
    throw suex::IOError("'%s' not owned my root:root", PATH_SUEX_TMP);
  }

  if (!S_ISDIR(fstat.st_mode)) {
    if (remove(PATH_SUEX_TMP) == 0) {
      return CreateRuntimeDirectories();
    }
    throw suex::IOError("'%s' is not a directory", PATH_SUEX_TMP);
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

  if (opts.EditConfig()) {
    EditConfiguration(opts, permissions);
    return 0;
  }

  // up to here, we don't check if the file is valid
  // because the edit config command can edit invalid files
  if (permissions.Empty()) {
    std::cerr << "! notice that you're not a member of 'wheel'" << std::endl;
    throw suex::PermissionError("suex.conf is either invalid or empty");
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

  std::vector<char *> environ;
  SwitchUserAndExecute(opts.AsUser(), opts.CommandArguments(),
                       GetEnv(&environ, permissions, opts));
  return 0;
}

int main(int argc, char *argv[]) {
  backward::SignalHandling sh;

  try {
    if (static_cast<int>(geteuid()) != RootUser().Id() ||
        static_cast<int>(getegid()) != RootUser().GroupId()) {
      throw suex::IOError("suex setid & setgid are no set");
    }
    OptArgs opts{argc, argv};
    if (opts.VerboseMode()) {
      TurnOnVerboseOutput();
    }
    auto permissions{Permissions(PATH_CONFIG, opts.AuthStyle()).Load()};
    return Do(permissions, opts);
  } catch (InvalidUsage &) {
    ShowUsage();
    return 1;
  } catch (SuExError &e) {
    std::cerr << e.what() << std::endl;
    return 1;
  } catch (std::exception &) {
    if (Permissions::Privileged()) {
      throw;
    }
    std::cerr << "an unhandled error occurred" << std::endl;
    return 1;
  }
}
