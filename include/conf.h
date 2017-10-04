#pragma once

#include <perm.h>
#include <iostream>
#include <regex>
#include "utils.h"

static auto opt_re_ = std::regex(R"(nopass|persist|keepenv|setenv\s\{.*\})");
//^(permit|deny)\s((.*)\s)?([a-z_][a-z0-9_-]*[$]?)\sas\s(((:)?[a-z_][a-z0-9_-]*[$]?)(:([a-z_][a-z0-9_-]*[$]?))?|\*)\scmd\s([^\s]+)(\s([^\s].*[^\s])[\s]*)?$
static auto bsd_re_ = std::regex(
    R"(^(permit|deny)\s((.*)\s)?([a-z_][a-z0-9_-]*[$]?)\sas\s(((:)?[a-z_][a-z0-9_-]*[$]?)(:([a-z_][a-z0-9_-]*[$]?))?|\*)\scmd\s([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
static auto line_re_ =
    std::regex(R"(^(%?[1-9a-zA-Z]+)\s->\s([1-9a-zA-Z]+)(:([1-9A-Za-z]+))?\s+::\s+([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
static auto comment_re_ = std::regex(R"(^[\t|\s]*#.*)");
static auto empty_re_ = std::regex(R"(^[\t|\s]*)");

class ExecutablePermissions {
 public:
  explicit ExecutablePermissions(User &user,
                                 User &as_user,
                                 bool deny,
                                 bool keepenv,
                                 bool nopass,
                                 bool persist,
                                 const std::string &cmd_re,
                                 const std::string &raw_txt) :
      user_{user},
      as_user_{as_user},
      deny_{deny},
      nopass_{nopass},
      keepenv_{keepenv},
      persist_{persist},
      cmd_re_{cmd_re},
      raw_txt_{raw_txt} {}

  const User &Me() const { return user_; };

  const User &AsUser() const { return as_user_; };

  bool PromptForPassword() const { return !nopass_; };

  bool CacheAuth() const { return !persist_; };

  bool KeepEnvironment() const { return keepenv_; };

  bool Deny() const { return deny_; };

  bool CanExecute(const User &user, const std::string &cmd) const;

  const std::string &ToString()  const { return raw_txt_;};

 private:

  User user_;
  bool deny_;
  bool nopass_;
  bool keepenv_;
  bool persist_;
  User as_user_;
  std::regex cmd_re_;
  std::string raw_txt_;
};

class Permissions {
 public:
  explicit Permissions(const std::string &path);

  const ExecutablePermissions *Get(const User &user,
                                   char *const *cmdargv) const;

 private:
  std::vector<ExecutablePermissions> perms_ = {};

  // match ' or " but not \' and \"
  // if that looks weird, a full explanation in the cpp file
  std::regex quote_re_ = std::regex(R"(('|")(?!\\))");

  bool Exists(const std::string &path) const;

  void Create(const std::string &path) const;

  void ParseLine(const std::string &line);

  void ValidatePermissions(const std::string &path) const;

  void Parse(const std::string &line);
};


