#pragma once

#include <optarg.h>
#include <perm.h>
#include <utils.h>
#include <regex>
#include <string>

namespace suex::permissions {

#define MAX_LINE 65535
#define MAX_FILESIZE 8192

static auto opt_re_ = std::regex(R"(nopass|persist|keepenv|setenv\s\{.*\})");

static auto line_re_ = std::regex(
    R"(^(permit|deny)\s((.*)\s)?((:)?[a-z_][a-z0-9_-]*[$]?)\sas\s([a-z_][a-z0-9_-]*[$]?)\scmd\s([^\s]+)(\sargs\s(([^\s].*[^\s])[\s]*))?$)");

static auto comment_re_ = std::regex(R"(^[\t|\s]*#.*)");

static auto empty_re_ = std::regex(R"(^[\t|\s]*)");

// match ' or " but not \' and \"
// if that looks weird, a full explanation in the cpp file
static auto quote_re_ = std::regex(R"(('|")(?!\\))");



class Permissions {
 private:
  typedef std::vector<Entity> Collection;
  std::string path_;
  std::string auth_service_;
  std::vector<Entity> perms_{};
  void Parse(int lineno, const std::string &line, bool only_user);

 public:
  typedef Collection::const_iterator const_iterator;

  explicit Permissions(const std::string &path, const std::string &auth_service,
                       bool only_user = true);

  static bool Validate(const std::string &path,
                       const std::string &auth_service);

  std::string AuthService() const { return auth_service_; }

  bool Privileged() const {
    return wheel_group.Contains(running_user) || running_user == root_user;
  }

  void Reload(bool only_user);

  const Entity *Get(const User &user, char *const *cmdargv) const;

  unsigned long Size() const { return perms_.size(); };

  const_iterator begin() const { return perms_.cbegin(); };

  const_iterator end() const { return perms_.cend(); };
};
}
