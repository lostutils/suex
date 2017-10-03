#pragma once

#include <conf.h>
#include <unistd.h>

std::string CommandArgsText(char *const *cmdargv);

void ValidateBinary(const std::string &path);

bool BypassPermissions(const User &as_user, const Group &as_group);

const std::string Iso8601();

const std::string ToString(char *txt);