#include <logger.h>
#include <conf.h>
#include <path.h>
#include <zconf.h>

void Permissions::validate_permissions(std::string &path) const {
    struct stat fstat{};
    stat(path.c_str(), &fstat);

    // config file can only have read permissions for user and group
    if (permbits(fstat) != 440) {
        std::stringstream ss;
        ss << "invalid permission bits: " << permbits(fstat);
        throw std::runtime_error(ss.str());
    }

    // config file has to be owned by root:root
    if (fstat.st_uid != 0 || fstat.st_gid != 0) {
        std::stringstream ss;
        ss << "invalid file owner: " << User(fstat.st_uid).name() << ":"
           << Group(fstat.st_gid).name();
        throw std::runtime_error(ss.str());
    }
}

const std::vector<ExecutablePermissions>::const_iterator Permissions::begin() const {
    return _perms.cbegin();
}

const std::vector<ExecutablePermissions>::const_iterator Permissions::end() const {
    return _perms.cend();
}

void Permissions::create(std::string &path) const {
    std::fstream fs;
    fs.open(path, std::ios::out);

    // chmod 440
    if (chmod(path.c_str(), S_IRUSR | S_IRGRP) < 0) {
        throw std::runtime_error(std::strerror(errno));
    }

    // chown root:root
    if (chown(path.c_str(), 0, 0) < 0) {
        throw std::runtime_error(std::strerror(errno));
    }
    fs.close();
}

bool Permissions::exists(std::string &path) const {
    std::ifstream f(path);
    bool exists = f.good();
    f.close();
    return exists;
}

void Permissions::load(std::string &path) {
    // create the file if it doesn't exist,
    // and set the right ownership and permission bits.
    if (!exists(path)) {
        create(path);
    }

    // check that the configurations file has the right
    // ownership and permissions
    validate_permissions(path);

    // parse each line in the configuration file
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        parse(line);
    }

    // TODO: RAII
    f.close();
}

std::vector<User> &addUsers(const std::string &user, std::vector<User> &users) {
    if (user[0] != '%') {
        users.emplace_back(User(user));
        return users;
    }

    // load the group members and add each one
    struct group *gr = getgrnam(user.substr(1, user.npos).c_str());

    if (gr == nullptr) {
        throw std::runtime_error("origin group doesn't exist");
    }

    for (auto it = gr->gr_mem; (*it) != nullptr; it++) {
        users.emplace_back(User(*it));
    }

    return users;
}

void Permissions::populate_permissions(std::smatch &matches) {

    // <user-or-group> -> <dest-user>:<dest-group> ::
    // <path-to-executable-and-args>
    std::vector<User> users;

    // first match is a user or group this line refers to
    // a string that starts with a '%' is a group (like in /etc/sudoers)
    for (User &user : addUsers(matches[1], users)) {
        if (!user.exists()) {
            std::stringstream ss;
            throw std::runtime_error("origin user doesn't exist");
        }
    }

    // extract the destination user
    User dest_user = User(matches[2]);
    if (!dest_user.exists()) {
        throw std::runtime_error("dest user doesn't exist");
    }

    // extract the destination group
    Group dest_group = Group(matches[4], dest_user);
    if (!dest_group.exists()) {
        throw std::runtime_error("dest group doesn't exist");
    }

    // extract the executable path.
    // don't try to locate the path in $PATH

    std::string cmd = getpath(matches[5], false);
    std::string args = matches[7];

    // if no args are passed, the user can execute *any* args
    // we remove single quotes because these don't actually exists,
    // the shell concatenates single-quoted-wrapped strings

    if (!args.empty()) {
        // the regex is reversed because c++11 doesn't support negative lookbehind.
        // instead, the regex has been reversed to look ahead.
        // this whole thing isn't too costly because the lines are short.
        std::reverse(args.begin(), args.end());
        args = std::regex_replace(args, quote_re, "");
        std::reverse(args.begin(), args.end());
    }

    cmd += args.empty() ? ".*" : "\\s+" + args;

    logger::debug << "command is: " << cmd << std::endl;
    std::regex cmd_re = std::regex(cmd);

    // populate the permissions vector
    for (User &user : users) {
        _perms.emplace_back(ExecutablePermissions(user, dest_user, dest_group, cmd_re));
    }
}

void Permissions::parse(std::string &line) {

    std::smatch matches;
    //  a comment, no need to parse
    if (std::regex_match(line, matches, comment_re)) {
        return;
    }

    //  an empty line, no need to parse
    if (std::regex_match(line, matches, empty_re)) {
        return;
    }

    logger::debug << "parsing line: " << line << std::endl;
    try {
        if (!std::regex_search(line, matches, line_re)) {
            throw std::runtime_error("couldn't parse line");
        }
        populate_permissions(matches);

    } catch (std::exception &e) {
        logger::error << "config error, skipping - " << e.what() << " [" << line << "]" << std::endl;
    }
}

const bool ExecutablePermissions::cmdcmp(const std::string &cmd) const {
    std::smatch matches;
    return std::regex_match(cmd, matches, _cmd_re);
}
