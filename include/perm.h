#pragma once

#include <grp.h>
#include <pwd.h>
#include <re2/re2.h>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace suex::permissions {

class User {
 public:
  explicit User() = default;

  User(const User &user);

  explicit User(uid_t uid);

  explicit User(const std::string &user);

  const std::string &Name() const { return name_; };

  bool operator==(const User &other) const;

  bool operator!=(const User &other) const;

  bool operator<(const User &other) const;

  bool operator>(const User &other) const;

  bool operator<=(const User &other) const;

  bool operator>=(const User &other) const;

  const int Id() const { return uid_; };

  int GroupId() const { return gid_; };

  const std::string &HomeDirectory() const { return home_dir_; };

  const std::string &Shell() const { return shell_; };

  bool Exists() const { return uid_ != -1; }

 private:
  std::string name_;
  int uid_{-1};
  int gid_{-1};
  std::string home_dir_;
  std::string shell_;
  void Initialize(const struct passwd *pw);
};

class Group {
 private:
  typedef std::set<User> Collection;

  std::string name_;
  int gid_{-1};
  std::set<User> members_;
  void Initialize(const struct group *gr);

 public:
  typedef Collection::const_iterator const_iterator;

  explicit Group(gid_t gid);

  explicit Group(const std::string &grp);

  Group(const Group &grp);

  const std::string &Name() const { return name_; };

  bool Contains(const User &user) const {
    return members_.find(user) != members_.end();
  };

  const_iterator begin() const { return members_.begin(); }

  const_iterator end() const { return members_.end(); }

  int Id() const { return gid_; };

  bool Exists() { return gid_ != -1; }

  bool operator==(const Group &other) const;

  bool operator!=(const Group &other) const;

  bool operator<(const Group &other) const;

  bool operator>(const Group &other) const;

  bool operator<=(const Group &other) const;

  bool operator>=(const Group &other) const;
};

class Entity {
 public:
  typedef std::set<std::string> EnvToRemove;
  typedef std::unordered_map<std::string, std::string> EnvToAdd;

  explicit Entity(const User &user, const User &as_user, bool deny,
                  bool keepenv, bool nopass, bool persist, EnvToAdd env_to_add,
                  EnvToRemove env_to_remove, const std::string &cmd_re)
      : user_{user},
        as_user_{as_user},
        deny_{deny},
        nopass_{nopass},
        keepenv_{keepenv},
        persist_{persist},
        cmd_re{cmd_re},
        env_to_add_{std::move(env_to_add)},
        env_to_remove{std::move(env_to_remove)} {}

  explicit Entity(const User &user, const User &as_user, bool deny,
                  bool keepenv, bool nopass, bool persist,
                  const std::string &cmd_re)
      : user_{user},
        as_user_{as_user},
        deny_{deny},
        nopass_{nopass},
        keepenv_{keepenv},
        persist_{persist},
        cmd_re{cmd_re},
        env_to_add_{},
        env_to_remove{} {}

  const User &Owner() const { return user_; };

  const User &AsUser() const { return as_user_; };

  bool PromptForPassword() const { return !nopass_; };

  bool CacheAuth() const { return persist_; };

  bool KeepEnvironment() const { return keepenv_; };

  bool EnvironmentVariablesConfigured() const {
    return !(env_to_add_.empty() && env_to_remove.empty());
  }

  bool ShouldAddEnvVar(const std::string &env) const {
    return env_to_add_.find(env) != env_to_add_.end();
  }

  const EnvToAdd EnvVarsToAdd() const { return env_to_add_; }

  bool ShouldRemoveEnvVar(const std::string &env) const {
    return env_to_remove.find(env) != env_to_remove.end();
  }

  bool Deny() const { return deny_; };

  bool CanExecute(const User &user, const std::string &cmd) const;

  const std::string &Command() const { return cmd_re; };

 private:
  User user_;
  User as_user_;
  bool deny_{true};
  bool nopass_{false};
  bool keepenv_{false};
  bool persist_{false};
  std::string cmd_re;
  EnvToAdd env_to_add_;
  EnvToRemove env_to_remove;
};
void Set(const User &user);
std::ostream &operator<<(std::ostream &os, const Entity &entity);
}
