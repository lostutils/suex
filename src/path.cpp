#include <zconf.h>
#include <sys/stat.h>
#include <cstring>
#include <fstream>
#include <sstream>

bool path_exists(const std::string &path) {
    std::ifstream f(path);
    bool exists = f.good();
    f.close();
    return exists;
}

const std::string getcwd() {
    char *buff = nullptr;//automatically cleaned when it exits scope
    return std::string(getcwd(buff, 255));
}

const std::string realpath(const std::string &path) {
    char buff[PATH_MAX] = {};
    if (realpath(path.c_str(), buff) == nullptr) {
        return path;
    }
    return std::string(buff);
}

std::string locatepath(const std::string &path, bool searchInPath) {
    std::string name(basename(path.c_str()));
    std::string fullpath = realpath(path);

    if (path_exists(fullpath)) {
        return fullpath;
    }

    char *pathenv = getenv("PATH");
    if (pathenv != nullptr && searchInPath) {
        std::istringstream iss(pathenv);
        while (getline(iss, fullpath, ':')) {
            fullpath += "/" + name;
            std::ifstream f(fullpath);
            if (f.good()) {
                return realpath(fullpath);
            }
        }
    }

    throw std::runtime_error("path '" + path + "' not found");
}

std::string getpath(const std::string &path, bool searchInPath) {
    std::string fullpath = locatepath(path, searchInPath);

    struct stat fstat{};
    if (stat(fullpath.c_str(), &fstat) != 0) {
        throw std::runtime_error(path + " : " + std::strerror(errno));
    }
    // path has to be a file
    if (!S_ISREG(fstat.st_mode)) {
        throw std::runtime_error(path + " is not a file");
    }

    return fullpath;
}

