#include <logger.h>
#include <utils.h>

const bool debugMode() {
    auto env = toString(std::getenv("RUNAS_DEBUG"));
    std::transform(env.begin(), env.end(), env.begin(), ::tolower);
    return env == "true" || env == "1";
};

const std::string typeName(logger::Type type) {
    switch (type) {
        case logger::Type::DEBUG:
            return "DEBUG";
        case logger::INFO:
            return "INFO";
        case logger::WARNING:
            return "WARNING";
        case logger::ERROR:
            return "ERROR";
        default:
            throw std::runtime_error("unknown logger");
    }
}

logger::Logger::Logger(logger::Type type) : _type(type), _name(typeName(type)), _user(getuid()), _fs() {
}

logger::Logger::Logger(const logger::Logger &other) {
    throw std::runtime_error("don't copy a logger, use the static ones.");
}

logger::Logger::~Logger() {
    if (_fs.is_open()) {
        _fs.close();
    }
}

std::ostream &logger::Logger::operator<<(const char *text) {
    std::string str{text};
    *this << str;
    return _fs;
}

std::ostream &logger::Logger::operator<<(std::string &text) {
    // don't log debug messages when the 'RUNAS_DEBUG' flag is not set.
    if (!debugMode() && _type == logger::DEBUG) {
        return _fs;
    }

    if (!_fs.is_open()) {
        _fs.open(LOG_PATH, std::ios::out | std::ios::app);
    }

    if (_fs.fail()) {
        throw std::runtime_error(std::strerror(errno));
    }

    _fs << iso8601() << " " << _name << " "
        << "[" << _user.name() << "]" << " - " << text;

    _fs.flush();
    return _fs;
}


