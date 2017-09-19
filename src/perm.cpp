#include <perm.h>
#include <unistd.h>
#include <vector>
#include <sstream>

int setgroups(User &user, Group &grp) {
    // walk through all the groups that a user has and set them
    int ngroups = 0;
    const char *name = user.name().c_str();
    std::vector<gid_t> groupvec;

    while (true) {
        if (getgrouplist(name, grp.id(), &groupvec.front(), &ngroups) < 0) {
            groupvec.resize(static_cast<unsigned long>(ngroups));
            continue;
        }
        return setgroups(static_cast<size_t>(ngroups), &groupvec.front());
    }
}

void setperm(User &user, Group &grp) {
    if (setgroups(user, grp) < 0) {
        std::stringstream ss;
        ss << "execution of setgroups(" << grp.id() << ") failed";
        throw std::runtime_error(ss.str());
    }

    if (setgid(grp.id()) < 0) {
        std::stringstream ss;
        ss << "execution of setgid(" << grp.id() << ") failed";
        throw std::runtime_error(ss.str());
    }

    if (setuid(user.id()) < 0) {
        std::stringstream ss;
        ss << "execution of setuid(" << user.id() << ") failed";
        throw std::runtime_error(ss.str());
    }
}

int permbits(struct stat &fstat) {
    // return permission bits in a "human readable" format
    int user = (fstat.st_mode & S_IRWXU) >> 6;
    int group = (fstat.st_mode & S_IRWXG) >> 3;
    int others = fstat.st_mode & S_IRWXO;
    return (user * 100) + (group * 10) + others;
}


User::User(uid_t uid) : _pw_uid(static_cast<uid_t>(-1)) {
    struct passwd *pw = getpwuid(uid);
    if (pw == nullptr) {
        return;

    }
    _pw_uid = pw->pw_uid;
    _pw_name = std::string(pw->pw_name);
    _pw_gid = pw->pw_gid;
    _pw_dir = std::string(pw->pw_dir);
}

User::User(const std::string &user) : _pw_uid(static_cast<uid_t>(-1)) {
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

    _pw_uid = pw->pw_uid;
    _pw_name = std::string(pw->pw_name);
    _pw_gid = pw->pw_gid;
    _pw_dir = std::string(pw->pw_dir);
}

bool User::exists() {
    return _pw_uid != -1;
}

Group::Group(gid_t gid) : _gr_gid(static_cast<gid_t>(-1)) {
    struct group *gr = getgrgid(gid);
    if (gr == nullptr) {
        return;
    }
    _gr_gid = gr->gr_gid;
    _gr_name = std::string(gr->gr_name);
}

Group::Group(const std::string &grp, User &user) : _gr_gid(static_cast<gid_t>(-1)) {
    // try to extract the group struct
    // if the group is empty, and the user exists -> use the user's group,
    //
    // otherwise, try to extract the extracted group.

    // if those fail, also try to load the group as a gid.
    if (grp.empty() && user.exists()) {
        _gr_gid = user.gid();
        _gr_name = std::string(getgrgid(user.gid())->gr_name);
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

    _gr_gid = gr->gr_gid;
    _gr_name = std::string(gr->gr_name);
}

bool Group::exists() {
    return _gr_gid != -1;

}
