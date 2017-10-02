#pragma once

#include <perm.h>
#include <iostream>
#include <regex>

class ExecutablePermissions {
 public:
  explicit ExecutablePermissions(User &user,
                                 User &as_user,
                                 Group &as_group, std::regex &cmd_re) : user_{user}, as_user_{as_user},
                                                                        as_group_{as_group},
                                                                        cmd_re_{cmd_re} {}

  const User &Me() const { return user_; };

  const User &AsUser() const { return as_user_; };

  const Group &AsGroup() const { return as_group_; };

  const bool CompareCommand(const std::string &cmd) const;

 private:
  User user_;
  User as_user_;
  Group as_group_;
  std::regex cmd_re_;
};

class Permissions {
 public:
  explicit Permissions(const std::string &path);

  const std::vector<ExecutablePermissions>::const_iterator begin() const;

  const std::vector<ExecutablePermissions>::const_iterator end() const;

 private:
  std::vector<ExecutablePermissions> perms_ = {};
  std::regex line_re_ = std::regex(
      R"(^(%?[1-9a-zA-Z]+)\s->\s([1-9a-zA-Z]+)(:([1-9A-Za-z]+))?\s+::\s+([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
  std::regex comment_re_ = std::regex(R"(^[\t|\s]*#.*)");
  std::regex empty_re_ = std::regex(R"(^[\t|\s]*)");

  // match ' or " but not \' and \"
  // if that looks weird, a full explanation in the cpp file
  std::regex quote_re_ = std::regex(R"(('|")(?!\\))");

  bool Exists(const std::string &path) const;

  void Create(const std::string &path) const;

  void PopulatePermissions(const std::smatch &matches);

  void ValidatePermissions(const std::string &path) const;

  void Parse(const std::string &line);
};


