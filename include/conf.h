#pragma once

#include <optarg.h>
#include <perm.h>
#include <re2/re2.h>
#include <utils.h>
#include <string>

namespace suex::permissions {

#define MAX_FILE_SIZE 8192

const RE2 &PermissionsOptionsRegex();
const RE2 &PermissionLineRegex();
const RE2 &CommentLineRegex();
const RE2 &EmptyLineRegex();

class Permissions {
 private:
  typedef std::vector<Entity> Collection;
  std::string auth_style_;
  std::vector<Entity> perms_{};
  void ParseLine(int lineno, const std::string &line);
  void LoadFile(int fd);

 public:
  typedef Collection::const_iterator const_iterator;

  explicit Permissions(const std::string &path, std::string auth_style);
  explicit Permissions(int fd, std::string auth_style);
  static bool Validate(int fd, const std::string &auth_style);

  std::string AuthStyle() const { return auth_style_; }

  static bool Privileged() {
    return WheelGroup().Contains(RunningUser()) || RunningUser() == RootUser();
  }

  const Entity *Get(const User &user, const std::vector<char *> &cmdargv) const;

  unsigned long Size() const { return perms_.size(); };

  const_iterator begin() const { return perms_.cbegin(); };

  const_iterator end() const { return perms_.cend(); };
};
}
