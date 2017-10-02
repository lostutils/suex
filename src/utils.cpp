#include <utils.h>
#include <iomanip>

std::string CommandArgsText(char *const *cmdargv) {
  std::stringstream ss;
  for (int i = 0; cmdargv[i] != nullptr; ++i) {
    std::string suffix = cmdargv[i + 1] != nullptr ? " " : "";
    ss << cmdargv[i] << suffix;
  }
  return ss.str();
}

void ValidateBinary(const std::string &path) {
  struct stat fstat{};

  if (stat(path.c_str(), &fstat) != 0) {
    throw std::runtime_error(path + " : " + std::strerror(errno));
  }

  if ((fstat.st_mode & S_ISUID) == 0) {
    throw std::runtime_error("SUID is not set on doas");
  }
  if (fstat.st_uid != 0 || fstat.st_gid != 0) {
    throw std::runtime_error("doas owner should be 'root:root'");
  }
}

bool can_execute(const User &user, const Group &group, const std::string &cmd,
                 const ExecutablePermissions &perm) {
  if (perm.Me().Id() != getuid()) {
    return false;
  }

  if (perm.AsUser().Id() != user.Id()) {
    return false;
  }

  if (perm.AsGroup().Id() != group.Id()) {
    return false;
  }

  return perm.CompareCommand(cmd);

}

bool HasPermissions(const Permissions &permissions, const User &user, const Group &group, char *const *cmdargv) {

  std::string cmd = std::string(*cmdargv);

  std::string cmdtxt{CommandArgsText(cmdargv)};
  for (const ExecutablePermissions &perm : permissions) {
    if (can_execute(user, group, cmdtxt, perm)) {
      return true;
    }
  }
  return false;
}

bool BypassPermissions(const User &running_user, const User &dest_user, const Group &dest_group) {

  // if the user / grp is root, just let them run.
  if (running_user.Id() == 0 && running_user.GroupId() == 0) {
    return true;
  }

  // if the user / grp are the same as the running user,
  // just run the app without performing any operations
  return running_user.Id() == dest_user.Id() && running_user.GroupId() == dest_group.Id();

}

const std::string Iso8601() {
  auto t = std::time(nullptr);
  auto tm = *std::localtime(&t);

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}

const std::string ToString(char *txt) {
  if (txt == nullptr) {
    return "";
  }
  return std::string(txt);
}
