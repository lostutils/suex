#pragma once

#include <functional>

#include <sys/stat.h>
#include <unistd.h>
#include <env.hpp>
#include <gsl/span>
#include <iostream>
#include <perm.hpp>
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

bool AskQuestion(const std::string &prompt);

std::string GetEditor();
}  // namespace suex::utils
