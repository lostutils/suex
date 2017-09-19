#include <utils.h>
#include <iomanip>
#include <optarg.h>
#include <logger.h>
#include <exceptions.h>

using namespace doas;
using namespace doas::optargs;
using namespace doas::permissions;
using namespace doas::utils;

std::string utils::CommandArgsText(char *const *cmdargv) {
  std::stringstream ss;
  for (int i = 0; cmdargv[i] != nullptr; ++i) {
    std::string suffix = cmdargv[i + 1] != nullptr ? " " : "";
    ss << cmdargv[i] << suffix;
  }
  return ss.str();
}

void utils::ValidateBinaryOwnership(const std::string &path) {
  struct stat fstat{};
  if (stat(path::Locate(path).c_str(), &fstat) != 0) {
    throw doas::PermissionError("couldn't locate doas binary");
  }

  if ((fstat.st_mode & S_ISUID) == 0) {
    throw doas::PermissionError("set user ID upon execution (suid) access not granted for '%s'", path.c_str());
  }

  if (fstat.st_uid != 0 || fstat.st_gid != 0) {
    throw doas::PermissionError("doas owner should be 'root:root'");
  }
}

bool utils::BypassPermissions(const User &as_user) {

  // if the user / grp is root, just let them run.
  if (running_user.Id() == 0 && running_user.GroupId() == 0) {
    return true;
  }

  // if the user / grp are the same as the running user,
  // just run the app without performing any operations
  return running_user.Id() == as_user.Id() && running_user.GroupId() == as_user.GroupId();

}

const std::string utils::Iso8601() {
  auto t = std::time(nullptr);
  auto tm = *std::localtime(&t);

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}

const std::string utils::ToString(char *txt) {
  if (txt == nullptr) {
    return "";
  }
  return std::string(txt);
}

int utils::PermissionBits(const struct stat &fstat) {
// return permission bits in a "human readable" format
  int user = (fstat.st_mode & S_IRWXU) >> 6;
  int group = (fstat.st_mode & S_IRWXG) >> 3;
  int others = fstat.st_mode & S_IRWXO;
  return (user * 100) + (group * 10) + others;
}
std::string utils::GetEditor() {
  std::string editor{env::Get("EDITOR")};

  while (true) {
    try {
      return path::Locate(editor);
    } catch (...) {
      std::cout << "$EDITOR is not set or invalid, please enter editor name: ";
      std::getline(std::cin, editor);
    }
  }
}

bool utils::AskQuestion(const std::string &prompt) {
  std::string ans;
  std::cout << prompt << " ";
  std::getline(std::cin, ans);
  std::smatch base_match;
  std::regex rx{"y|yes", std::regex_constants::icase};
  return std::regex_match(ans, base_match, rx);
}

