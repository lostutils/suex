#pragma once

#include <perm.h>
#include <iostream>
#include <regex>
#include "utils.h"

static auto opt_re_ = std::regex(R"(nopass|persist|keepenv|setenv\s\{.*\})");
static auto bsd_re_ = std::regex(
    R"(^(permit|deny)\s((.*)\s)?([a-z_][a-z0-9_-]*[$]?)\sas\s(([a-z_][a-z0-9_-]*[$]?)|\*)\scmd\s([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
static auto line_re_ =
    std::regex(R"(^(%?[1-9a-zA-Z]+)\s->\s([1-9a-zA-Z]+)(:([1-9A-Za-z]+))?\s+::\s+([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
static auto comment_re_ = std::regex(R"(^[\t|\s]*#.*)");
static auto empty_re_ = std::regex(R"(^[\t|\s]*)");

class ExecutablePermissions {
 public:
  explicit ExecutablePermissions(User &user,
                                 User &as_user,
                                 Group &as_group,
                                 std::regex &cmd_re) :
      user_{user},
      as_user_{as_user},
      as_group_{as_group},
      cmd_re_{cmd_re} {}

  const User &Me() const { return user_; };

  const User &AsUser() const { return as_user_; };

  const Group &AsGroup() const { return as_group_; };

  bool CanExecute(const User &user, const Group &group, const std::string &cmd) const;

 private:

  User user_;
  User as_user_;
  Group as_group_;
  std::regex cmd_re_;
};

class Permissions {
 public:
  explicit Permissions(const std::string &path);

  const ExecutablePermissions *Get(const User &user,
                                   const Group &group,
                                   char *const *cmdargv) const;

 private:
  std::vector<ExecutablePermissions> perms_ = {};

  // match ' or " but not \' and \"
  // if that looks weird, a full explanation in the cpp file
  std::regex quote_re_ = std::regex(R"(('|")(?!\\))");

  bool Exists(const std::string &path) const;

  void Create(const std::string &path) const;

  void PopulatePermissions(const std::smatch &matches);

  void ValidatePermissions(const std::string &path) const;

  void Parse(const std::string &line);
};


