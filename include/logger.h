#pragma once

#include <path.h>
#include <perm.h>
#include <fstream>
#include <iostream>
#include <ostream>
#include <string>

namespace suex::logger {

enum Type { DEBUG, INFO, WARNING, ERROR };

class Logger {
 public:
  static Logger &get(Type type);
  void VerboseOn() { verbose_ = true; }

  ~Logger() = default;

  std::ostream &operator<<(const char *text);

  std::ostream &operator<<(const std::string &text);

 private:
  std::ostream &Stream() {
    static std::ofstream devnull{PATH_DEV_NULL};

    if (verbose_) {
      return std::clog;
    }
    return devnull;
  }

  explicit Logger(Type type);
  Logger(const Logger &other);
  Type type_;
  permissions::User user_{};
  bool verbose_{false};
};

Logger &debug();

Logger &info();

Logger &warning();

Logger &error();
};  // namespace suex::logger
