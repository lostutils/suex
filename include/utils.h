#pragma once

#include <functional>

#include <env.h>
#include <perm.h>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

static const auto running_user = suex::permissions::User(getuid());
static const auto root_user = suex::permissions::User(0);
static const auto wheel_group = suex::permissions::Group("wheel");

#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)
#define DEFER(fn) ScopeGuard CONCAT(__defer__, __LINE__) = [&]() { fn; }

class ScopeGuard {
 public:
  template<class Callable>
  ScopeGuard(Callable &&fn) : fn_(std::forward<Callable>(fn)) {}

  ScopeGuard(ScopeGuard &&other) : fn_(std::move(other.fn_)) {
    other.fn_ = nullptr;
  }

  ~ScopeGuard() {
    // must not throw
    if (fn_) fn_();
  }

  ScopeGuard(const ScopeGuard &) = delete;

  void operator=(const ScopeGuard &) = delete;

 private:
  std::function<void()> fn_;
};

namespace suex::utils {
std::string CommandArgsText(char *const *cmdargv);

bool BypassPermissions(const suex::permissions::User &as_user);

const std::string Iso8601();

const std::string ToString(char *txt);

bool AskQuestion(const std::string &prompt);

std::string GetEditor();

// https://stackoverflow.com/a/26221725/4579708
template<typename... Args>
std::string StringFormat(const std::string &format, Args &&... args) {
  // Extra space for '\0'
  size_t size = (size_t) snprintf(nullptr, 0, format.c_str(), args...) + 1;
  std::unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), size, format.c_str(), args...);
  // We don't want the '\0' inside
  return std::string(buf.get(), buf.get() + size - 1);
}
}
