#include <logger.h>
#include <utils.h>

const bool DebugMode() {
  auto env = ToString(std::getenv("DOAS_DEBUG"));
  std::transform(env.begin(), env.end(), env.begin(), ::tolower);
  return env == "true" || env == "1";
};

const std::string TypeName(logger::Type type) {
  switch (type) {
    case logger::Type::DEBUG:return "DEBUG";
    case logger::INFO:return "INFO";
    case logger::WARNING:return "WARNING";
    case logger::ERROR:return "ERROR";
    default:throw std::runtime_error("unknown logger");
  }
}

logger::Logger::Logger(logger::Type type) : type_(type), name_(TypeName(type)), user_(getuid()), fs_() {
}

logger::Logger::Logger(const logger::Logger &other) {
  throw std::runtime_error("don't copy a logger, use the static ones.");
}

logger::Logger::~Logger() {
  if (fs_.is_open()) {
    fs_.close();
  }
}

std::ostream &logger::Logger::operator<<(const char *text) {
  std::string str{text};
  *this << str;
  return fs_;
}

std::ostream &logger::Logger::operator<<(std::string &text) {
  // don't log debug messages when the 'DOAS_DEBUG' flag is not set.
  if (!DebugMode() && type_ == logger::DEBUG) {
    return fs_;
  }

  if (!fs_.is_open()) {
    fs_.open(LOG_PATH, std::ios::out | std::ios::app);
  }

  if (fs_.fail()) {
    throw std::runtime_error(std::strerror(errno));
  }

  fs_ << Iso8601() << " " << name_ << " "
      << "[" << user_.Name() << "]" << " - " << text;

  fs_.flush();
  return fs_;
}


