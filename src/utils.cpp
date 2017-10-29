#include <exceptions.h>
#include <logger.h>
#include <optarg.h>
#include <iomanip>

using namespace suex;
using namespace suex::optargs;
using namespace suex::permissions;
using namespace suex::utils;

std::string utils::CommandArgsText(char *const *cmdargv) {
  std::stringstream ss;
  for (int i = 0; cmdargv[i] != nullptr; ++i) {
    std::string suffix = cmdargv[i + 1] != nullptr ? " " : "";
    ss << cmdargv[i] << suffix;
  }
  return ss.str();
}

bool utils::BypassPermissions(const User &as_user) {
  // if the user / grp is root, just let them run.
  if (running_user.Id() == 0 && running_user.GroupId() == 0) {
    return true;
  }

  // if the user / grp are the same as the running user,
  // just run the app without performing any operations
  return running_user.Id() == as_user.Id() &&
      running_user.GroupId() == as_user.GroupId();
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
