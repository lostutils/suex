#include <perm.h>
#include <unistd.h>
#include <vector>
#include <sstream>

int setgroups(const User &user) {
  // walk through all the groups that a user has and set them
  int ngroups = 0;
  const char *name = user.Name().c_str();
  std::vector<gid_t> groupvec;

  while (true) {
    if (getgrouplist(name, user.GroupId(), &groupvec.front(), &ngroups) < 0) {
      groupvec.resize(static_cast<unsigned long>(ngroups));
      continue;
    }
    return setgroups(static_cast<size_t>(ngroups), &groupvec.front());
  }
}

void SetPermissions(const User &user) {
  if (setgroups(user) < 0) {
    std::stringstream ss;
    ss << "execution of setgroups(" << user.GroupId() << ") failed";
    throw std::runtime_error(ss.str());
  }

  if (setgid(user.GroupId()) < 0) {
    std::stringstream ss;
    ss << "execution of setgid(" << user.GroupId() << ") failed";
    throw std::runtime_error(ss.str());
  }

  if (setuid(user.Id()) < 0) {
    std::stringstream ss;
    ss << "execution of setuid(" << user.Id() << ") failed";
    throw std::runtime_error(ss.str());
  }
}

int PermissionBits(const struct stat &fstat) {
  // return permission bits in a "human readable" format
  int user = (fstat.st_mode & S_IRWXU) >> 6;
  int group = (fstat.st_mode & S_IRWXG) >> 3;
  int others = fstat.st_mode & S_IRWXO;
  return (user * 100) + (group * 10) + others;
}

User::User(uid_t uid) : pw_uid_(static_cast<uid_t>(-1)) {
  struct passwd *pw = getpwuid(uid);
  if (pw == nullptr) {
    return;

  }
  pw_uid_ = pw->pw_uid;
  pw_name_ = std::string(pw->pw_name);
  pw_gid_ = pw->pw_gid;
  pw_dir_ = std::string(pw->pw_dir);
}

User::User(const std::string &user) : pw_uid_(static_cast<uid_t>(-1)) {
  // try to extract the password struct
  // if the user is empty, use the current user,
  // otherwise try to take the one that was passed.

  // if both fail, also try to load the user as a uid.
  struct passwd *pw = user.empty() ? getpwuid(getuid()) : getpwnam(user.c_str());

  if (pw == nullptr) {
    try {
      pw = getpwuid(static_cast<uid_t>(std::stol(user, nullptr, 10)));

    } catch (std::invalid_argument &) {
      // the user wasn't found
      return;
    }
  }

  pw_uid_ = pw->pw_uid;
  pw_name_ = std::string(pw->pw_name);
  pw_gid_ = pw->pw_gid;
  pw_dir_ = std::string(pw->pw_dir);
}

bool User::Exists() {
  return pw_uid_ != -1;
}

Group::Group(gid_t gid) : gr_gid_(static_cast<gid_t>(-1)) {
  struct group *gr = getgrgid(gid);
  if (gr == nullptr) {
    return;
  }
  gr_gid_ = gr->gr_gid;
  gr_name_ = std::string(gr->gr_name);
}

Group::Group(const std::string &grp, User &user) : gr_gid_(static_cast<gid_t>(-1)) {
  // try to extract the group struct
  // if the group is empty, and the user exists -> use the user's group,
  //
  // otherwise, try to extract the extracted group.

  // if those fail, also try to load the group as a gid.
  if (grp.empty() && user.Exists()) {
    gr_gid_ = user.GroupId();
    gr_name_ = std::string(getgrgid(user.GroupId())->gr_name);
    return;
  }

  struct group *gr = getgrnam(grp.c_str());
  if (gr == nullptr) {
    try {
      gr = getgrgid(static_cast<gid_t>(std::stol(grp, nullptr, 10)));

    } catch (std::invalid_argument &) {
      return;
    }
  }

  gr_gid_ = gr->gr_gid;
  gr_name_ = std::string(gr->gr_name);
}

bool Group::Exists() {
  return gr_gid_ != -1;

}
