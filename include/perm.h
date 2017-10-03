#pragma once

#include <string>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <zconf.h>


class User {
 public:
  explicit User() = default;

  explicit User(uid_t uid);

  explicit User(const std::string &user);

  const std::string Name() const { return pw_name_; };

  const uid_t Id() const { return pw_uid_; };

  const gid_t GroupId() const { return pw_gid_; };

  const std::string HomeDirectory() const { return pw_dir_; };

  bool Exists();

 private:
  std::string pw_name_;
  uid_t pw_uid_{};
  gid_t pw_gid_{};
  std::string pw_dir_;
};

class Group {
 public:
  explicit Group(gid_t gid);

  explicit Group(const std::string &grp, User &user);

  const std::string &Name() const { return gr_name_; };

  const uid_t &Id() const { return gr_gid_; };

  bool Exists();

 private:
  gid_t gr_gid_;
  std::string gr_name_;
};

void SetPermissions(const User &user);

int PermissionBits(const struct stat &fstat);
