#pragma once

#include <fstream>
#include <ostream>
#include <perm.h>
#include <iostream>
#include <path.h>

using namespace doas;

namespace doas::logger {

enum Type {
  DEBUG,
  INFO,
  WARNING,
  ERROR
};

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
  permissions::User user_{};
  Type type_;
  bool verbose_{false};
};

static Logger &debug() {
  return Logger::get(Type::DEBUG);
}

static Logger &info() {
  return Logger::get(Type::INFO);
}

static Logger &warning() {
  return Logger::get(Type::WARNING);
}

static Logger &error() {
  return Logger::get(Type::ERROR);
}

};

