#include <exceptions.h>
#include <fcntl.h>
#include <logger.h>
#include <sys/sendfile.h>
#include <climits>

using namespace suex;
using namespace suex::utils;

const std::string path::Real(const std::string &path) {
  char buff[PATH_MAX] = {};
  if (realpath(path.c_str(), buff) == nullptr) {
    logger::warning() << "couldn't locate '" << path << "'" << std::endl;
    return path;
  }
  logger::debug() << "located '" << path << "': " << buff << std::endl;
  return std::string(buff);
}

const std::string path::Locate(const std::string &path, bool searchInPath) {
  if (path.empty()) {
    throw suex::IOError("path '%s' is empty", path.c_str());
  }

  struct stat fstat{};
  std::string fullpath{Real(path)};
  if (stat(fullpath.c_str(), &fstat) == 0 && S_ISREG(fstat.st_mode)) {
    return fullpath;
  }

  std::string name(basename(path.c_str()));
  if (env::Contains("PATH") && searchInPath) {
    std::istringstream iss(env::Get("PATH"));
    std::string dir;
    while (getline(iss, dir, ':')) {
      fullpath = Real(StringFormat("%s/%s", dir.c_str(), name.c_str()));
      if (stat(fullpath.c_str(), &fstat) == 0 && S_ISREG(fstat.st_mode)) {
        return fullpath;
      }
    }
  }

  throw suex::IOError("path '%s' doesn't exist", path.c_str());
}

bool path::Exists(const std::string &path) {
  struct stat fstat{};
  return stat(path.c_str(), &fstat) == 0;
}

