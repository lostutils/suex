#pragma once

#include <string>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

class User {
public:
    explicit User() = default;

    explicit User(uid_t uid);

    explicit User(const std::string &user);

    const std::string name() const { return _pw_name; };

    const uid_t id() const { return _pw_uid; };

    const gid_t gid() const { return _pw_gid; };

    const std::string dir() const { return _pw_dir; };

    bool exists();

private:
    std::string _pw_name;
    uid_t _pw_uid{};
    gid_t _pw_gid{};
    std::string _pw_dir;
};


class Group {
public:
    explicit Group(gid_t gid);

    explicit Group(const std::string &grp, User &user);

    const std::string name() { return _gr_name; };

    uid_t id() const { return _gr_gid; };

    bool exists();

private:
    gid_t _gr_gid;
    std::string _gr_name;
};

void setperm(User &user, Group &grp);

int permbits(struct stat &fstat);
