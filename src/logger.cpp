#include <logger.h>
#include <utils.h>

using namespace suex;
using namespace suex::logger;

const std::string TypeName(Type type) {
  switch (type) {
    case Type::DEBUG:return "DEBUG";
    case INFO:return "INFO";
    case WARNING:return "WARNING";
    case ERROR:return "ERROR";
    default: { throw std::runtime_error("unknown logger"); }
  }
}

Logger::Logger(Type type) : type_(type), user_(running_user) {}

Logger::Logger(const Logger &other) {
  throw std::runtime_error("don't copy a logger, use the static ones.");
}

std::ostream &Logger::operator<<(const char *text) {
  std::string str{text};
  *this << str;

  return Stream();
}

std::ostream &Logger::operator<<(const std::string &text) {
  Stream() << TypeName(type_) << " - " << text;
  return Stream();
}

Logger &Logger::get(Type type) {
  static Logger debug = Logger(Type::DEBUG);
  static Logger info = Logger(Type::INFO);
  static Logger warning = Logger(Type::WARNING);
  static Logger error = Logger(Type::ERROR);

  if (type == Type::DEBUG) return debug;
  if (type == Type::INFO) return info;
  if (type == Type::WARNING) return warning;
  if (type == Type::ERROR) return error;

  throw std::runtime_error("unknown logger type");
}

Logger &logger::debug() { return Logger::get(Type::DEBUG); }

Logger &logger::info() { return Logger::get(Type::INFO); }

Logger &logger::warning() { return Logger::get(Type::WARNING); }

Logger &logger::error() { return Logger::get(Type::ERROR); }
