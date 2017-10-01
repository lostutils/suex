#pragma once

#include <conf.h>
#include <unistd.h>

std::string cmdargv_txt(const std::vector<char *> &cmdargv);

void validate_binary(const std::string &path);

bool hasperm(Permissions &permissions, User &user, Group &grp, std::vector<char *> cmdargv);

bool bypass_perms(User &running_user, User &dest_user, Group &dest_group);

const std::string iso8601();

const std::string toString(char *txt);