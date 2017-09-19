#pragma  once
#include <utils.h>
#include <stdexcept>

namespace doas {

class DoAsError : public std::runtime_error {
 public:
  explicit DoAsError(const std::string &text) : runtime_error(text) {}

  template<typename ... Args>
  explicit DoAsError(const std::string &format, Args &&... args) :
      runtime_error(utils::StringFormat(format, std::forward<Args>(args)...)) {}
};

class OptionError : public DoAsError {
 public:
  explicit OptionError(const std::string &text) : DoAsError(text) {}
  template<typename ... Args>
  explicit OptionError(const std::string &format, Args &&... args) :
      DoAsError(format, std::forward<Args>(args)...) {}
};

class PermissionError : public DoAsError {
 public:
  explicit PermissionError(const std::string &text) : DoAsError(text) {}
  template<typename ... Args>
  explicit PermissionError(const std::string &format, Args &&... args) :
      DoAsError(format, std::forward<Args>(args)...) {}
};

class AuthError : public PermissionError {
 public:
  explicit AuthError(const std::string &text) : PermissionError(text) {}
  template<typename ... Args>
  explicit AuthError(const std::string &format, Args &&... args) :
      PermissionError(format, std::forward<Args>(args)...) {}
};

class IOError : public DoAsError {
 public:
  explicit IOError(const std::string &text) : DoAsError(text) {}
  template<typename ... Args>
  explicit IOError(const std::string &format, Args &&... args) :
      DoAsError(format, std::forward<Args>(args)...) {}
};

class ConfigError : public DoAsError {
 public:
  explicit ConfigError(const std::string &text) : DoAsError(text) {}
  template<typename ... Args>
  explicit ConfigError(const std::string &format, Args &&... args) :
      DoAsError(format, std::forward<Args>(args)...) {}
};

}
