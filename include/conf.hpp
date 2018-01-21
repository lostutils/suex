#pragma once

#include <re2/re2.h>
#include <file.hpp>
#include <optarg.hpp>
#include <perm.hpp>
#include <string>
#include <utils.hpp>

namespace suex::permissions {

#define MAX_FILE_SIZE (8192 * 1024)

const RE2 &PermissionsOptionsRegex();
const RE2 &PermissionLineRegex();
const RE2 &CommentLineRegex();
const RE2 &EmptyLineRegex();

class Permissions {
 private:
  typedef std::vector<Entity> Collection;

  std::string auth_style_;
  std::vector<Entity> perms_{};
  file::File f_;

  void Parse(const file::line_t &line,
             std::function<void(const Entity &)> &&callback);

 public:
  typedef Collection::const_iterator const_iterator;

  Permissions(Permissions &other) noexcept;

  Permissions(const Permissions &) = delete;

  ~Permissions() = default;

  void operator=(const Permissions &) = delete;

  Permissions &Load();

  Permissions &Reload();

  explicit Permissions(const std::string &path, std::string auth_style);

  explicit Permissions(file::File &f, std::string auth_style);

  std::string AuthStyle() const { return auth_style_; }

  static bool Privileged() {
    return WheelGroup().Contains(RunningUser()) || RunningUser() == RootUser();
  }

  const Entity *Get(const User &user, const std::vector<char *> &cmdargv) const;

  unsigned long Size() const { return perms_.size(); };

  bool Empty() const { return perms_.empty(); };

  const_iterator begin() const { return perms_.cbegin(); };

  const_iterator end() const { return perms_.cend(); };
};
}
