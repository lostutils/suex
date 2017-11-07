#include <exceptions.h>
#include <logger.h>
#include <gsl/gsl>
#include <iomanip>

using suex::permissions::User;

std::string utils::CommandArgsText(const std::vector<char *> &cmdargv) {
  std::stringstream ss;

  auto span = gsl::make_span(cmdargv);

  for (char *q : span.subspan(0, cmdargv.size() - 2)) {
    ss << q << " ";
  }

  ss << span[cmdargv.size() - 2];

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
