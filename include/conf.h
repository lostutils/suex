#pragma once

#include <file.h>
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

struct Line {
  std::string txt;
  int lineno;
};

class Permissions {
 private:
  typedef std::vector<Entity> Collection;
  std::string auth_style_;
  std::vector<Entity> perms_{};
  int fd_{-1};
  bool auto_close_{false};
  void Parse(const struct Line &line,
             std::function<void(const Entity &)> &&callback);

 public:
  typedef Collection::const_iterator const_iterator;

  Permissions(Permissions &other) noexcept;

  ~Permissions();

  Permissions(const Permissions &) = delete;

  void operator=(const Permissions &) = delete;

  Permissions &Load();

  explicit Permissions(const std::string &path, std::string auth_style);

  explicit Permissions(int fd, std::string auth_style);

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
