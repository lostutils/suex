#pragma once

#include <optarg.h>
#include <perm.h>
#include <utils.h>
#include <regex>
#include <string>

namespace suex::permissions {

#define MAX_LINE 65535
#define MAX_FILE_SIZE 8192

const std::regex &PermissionsOptionsRegex();
const std::regex &PermissionLineRegex();
const std::regex &CommentLineRegex();
const std::regex &EmptyLineRegex();
const std::regex &QuoteLineRegex();

class Permissions {
 private:
  typedef std::vector<Entity> Collection;
  std::string auth_style_;
  bool secure_;
  std::vector<Entity> perms_{};
  void ParseLine(int lineno, const std::string &line, bool only_user);
  void Parse(const std::string &path, bool only_user);

 public:
  typedef Collection::const_iterator const_iterator;

  explicit Permissions(const std::string &path, std::string auth_style,
                       bool only_user = true);

  static bool Validate(const std::string &path, const std::string &auth_style);

  std::string AuthStyle() const { return auth_style_; }

  bool Privileged() const {
    return WheelGroup().Contains(RunningUser()) || RunningUser() == RootUser();
  }

  const Entity *Get(const User &user, const std::vector<char *> &cmdargv) const;

  unsigned long Size() const { return perms_.size(); };

  const_iterator begin() const { return perms_.cbegin(); };

  const_iterator end() const { return perms_.cend(); };
};
}
