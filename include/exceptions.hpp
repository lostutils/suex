#pragma once
#include <fmt.hpp>
#include <stdexcept>
#include <utils.hpp>

namespace suex {

class SuExError : public std::runtime_error {
 public:
  explicit SuExError(const std::string &text) : runtime_error(text) {}

  template <typename... Args>
  explicit SuExError(const std::string &format, Args &&... args)
      : runtime_error(Sprintf(format, std::forward<Args>(args)...)) {}
};

class InvalidUsage : public SuExError {
 public:
  explicit InvalidUsage() : SuExError("") {}
};

class PermissionError : public SuExError {
 public:
  explicit PermissionError(const std::string &text) : SuExError(text) {}
  template <typename... Args>
  explicit PermissionError(const std::string &format, Args &&... args)
      : SuExError(format, std::forward<Args>(args)...) {}
};

class AuthError : public PermissionError {
 public:
  explicit AuthError(const std::string &text) : PermissionError(text) {}
  template <typename... Args>
  explicit AuthError(const std::string &format, Args &&... args)
      : PermissionError(format, std::forward<Args>(args)...) {}
};

class IOError : public SuExError {
 public:
  explicit IOError(const std::string &text) : SuExError(text) {}
  template <typename... Args>
  explicit IOError(const std::string &format, Args &&... args)
      : SuExError(format, std::forward<Args>(args)...) {}
};

class ConfigError : public SuExError {
 public:
  explicit ConfigError(const std::string &text) : SuExError(text) {}
  template <typename... Args>
  explicit ConfigError(const std::string &format, Args &&... args)
      : SuExError(format, std::forward<Args>(args)...) {}
};
}  // namespace suex
