#pragma once

#include <perm.h>
#include <iostream>
#include <regex>

#define DEFAULT_CONFIG_PATH "/etc/runas.conf"

class ExecutablePermissions {
public:
    explicit ExecutablePermissions(User &user,
                                   User &dest_user,
                                   Group &dest_group, std::regex &cmd_re) : _user{user}, _dest_user{dest_user},
                                                                            _dest_group{dest_group},
                                                                            _cmd_re{cmd_re} {}

    const User user() const { return _user; };

    const User dest_user() const { return _dest_user; };

    const Group dest_group() const { return _dest_group; };

    const bool cmdcmp(const std::string &cmd) const;

private:
    User _user;
    User _dest_user;
    Group _dest_group;
    std::regex _cmd_re;
};

class Permissions {
public:
    void load(std::string &path);

    const std::vector<ExecutablePermissions>::const_iterator begin() const;

    const std::vector<ExecutablePermissions>::const_iterator end() const;

private:
    std::vector<ExecutablePermissions> _perms = {};
    std::regex line_re = std::regex(
            R"(^(%?[1-9a-zA-Z]+)\s->\s([1-9a-zA-Z]+)(:([1-9A-Za-z]+))?\s+::\s+([^\s]+)(\s([^\s].*[^\s])[\s]*)?$)");
    std::regex comment_re = std::regex(R"(^[\t|\s]*#.*)");
    std::regex empty_re = std::regex(R"(^[\t|\s]*)");

    // match ' or " but not \' and \"
    // if that looks weird, a full explanation in the cpp file
    std::regex quote_re = std::regex(R"(('|")(?!\\))");

    bool exists(std::string &path) const;

    void create(std::string &path) const;

    void populate_permissions(std::smatch &matches);

    void validate_permissions(std::string &path) const;

    void parse(std::string &line);
};


