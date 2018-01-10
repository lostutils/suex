#pragma once

#include <functional>

#include <env.h>
#include <perm.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gsl/span>
#include <iostream>
#include <vector>

const suex::permissions::User &RunningUser();
const suex::permissions::User &RootUser();
const suex::permissions::Group &WheelGroup();

#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)
#define DEFER(fn) auto CONCAT(__defer__, __LINE__) = gsl::finally([&] { fn; });

namespace suex::utils {
std::string CommandArgsText(const std::vector<char *> &cmdargv);
template <typename T>
inline T *ConstCorrect(T const *ptr) {
  return const_cast<T *>(ptr);
}

bool BypassPermissions(const suex::permissions::User &as_user);

const std::string Iso8601();

const std::string ToString(char *txt);

bool AskQuestion(const std::string &prompt);

std::string GetEditor();
}
