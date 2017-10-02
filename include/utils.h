#pragma once

#include <conf.h>
#include <unistd.h>

std::string CommandArgsText(char *const *cmdargv);

void ValidateBinary(const std::string &path);

bool HasPermissions(const Permissions &permissions, const User &user, const Group &grp, char *const *cmdargv);

bool BypassPermissions(const User &running_user, const User &dest_user, const Group &dest_group);

const std::string Iso8601();

const std::string ToString(char *txt);