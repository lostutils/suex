#include <zconf.h>
#include <sys/stat.h>
#include <cstring>
#include <fstream>
#include <sstream>

bool PathExists(const std::string &path) {
  std::ifstream f(path);
  bool exists = f.good();
  f.close();
  return exists;
}

const std::string RealPath(const std::string &path) {
  char buff[PATH_MAX] = {};
  if (realpath(path.c_str(), buff) == nullptr) {
    return path;
  }
  return std::string(buff);
}

const std::string LocatePath(const std::string &path, bool searchInPath) {
  std::string name(basename(path.c_str()));
  std::string fullpath = RealPath(path);

  if (PathExists(fullpath)) {
    return fullpath;
  }

  char *pathenv = getenv("PATH");
  if (pathenv != nullptr && searchInPath) {
    std::istringstream iss(pathenv);
    while (getline(iss, fullpath, ':')) {
      fullpath += "/" + name;
      std::ifstream f(fullpath);
      if (f.good()) {
        return RealPath(fullpath);
      }
    }
  }

  throw std::runtime_error("path '" + path + "' not found");
}

const std::string GetPath(const std::string &path, bool searchInPath) {
  std::string fullpath = LocatePath(path, searchInPath);

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

