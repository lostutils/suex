#pragma once

#include <perm.h>
#include <fstream>
#include <ostream>

#define LOG_PATH "/var/log/runas.log"

namespace logger {

    enum Type {
        DEBUG,
        INFO,
        WARNING,
        ERROR
    };

    class Logger {
    public:
        explicit Logger(Type type);

        Logger(const Logger &other);

        ~Logger();

        std::ostream &operator<<(const char *text);

        std::ostream &operator<<(std::string &text);

    private:
        User _user{};
        std::string _name;
        Type _type;
        std::ofstream _fs;
    };

    static Logger debug = Logger(Type::DEBUG);
    static Logger info = Logger(Type::INFO);
    static Logger warning = Logger(Type::WARNING);
    static Logger error = Logger(Type::ERROR);
}


