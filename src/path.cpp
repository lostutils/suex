#include <cstring>
#include <fstream>
#include <sstream>
#include <path.h>
#include <utils.h>
#include <exceptions.h>
#include <climits>
#include <logger.h>
#include <sys/sendfile.h>
#include <fcntl.h>

using namespace doas;
using namespace doas::utils;

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
    throw doas::IOError("path '%s' is empty", path.c_str());
  }

  struct stat fstat{};
  std::string fullpath{Real(path)};
  if (stat(fullpath.c_str(), &fstat) == 0 &&
      S_ISREG(fstat.st_mode)) {

    return fullpath;
  }

  std::string name(basename(path.c_str()));
  if (env::Contains("PATH") && searchInPath) {
    std::istringstream iss(env::Get("PATH"));
    std::string dir;
    while (getline(iss, dir, ':')) {
      fullpath = Real(StringFormat("%s/%s", dir.c_str(), name.c_str()));
      if (stat(fullpath.c_str(), &fstat) == 0 &&
          S_ISREG(fstat.st_mode)) {
        return fullpath;
      }
    }
  }

  throw doas::IOError("path '%s' doesn't exist", path.c_str());
}

bool path::Exists(const std::string &path) {
  std::ifstream f(path);
  DEFER(f.close());
  return f.good();
}

void path::Copy(const std::string &source, const std::string &dest) {
  int src_fd = open(source.c_str(), O_RDONLY, 0);
  DEFER(close(src_fd));
  int dst_fd = open(dest.c_str(), O_WRONLY | O_CREAT, 0440);
  DEFER(close(dst_fd));

  struct stat fstat{};
  if (stat(source.c_str(), &fstat) != 0) {
    throw doas::IOError("%s: %s", source.c_str(), std::strerror(errno));
  }

  if (sendfile(dst_fd,
               src_fd,
               nullptr,
               (size_t) fstat.st_size) <= 0) {
    throw doas::IOError("%s: %s", source.c_str(), std::strerror(errno));
  }
}
void path::Move(const std::string &source, const std::string &dest) {
  struct stat fstat{};
  if (stat(source.c_str(), &fstat) != 0) {
    throw doas::IOError("%s: %s", dest.c_str(), std::strerror(errno));
  }

  if (stat(dest.c_str(), &fstat) == 0) {
    if (remove(dest.c_str()) != 0) {
      throw doas::IOError("%s: %s", dest.c_str(), std::strerror(errno));
    }
  }

  Copy(source, dest);

  if (remove(source.c_str()) != 0) {
    throw doas::IOError("%s: %s", source.c_str(), std::strerror(errno));
  }
}
void path::Touch(const std::string &pathname) {
  if (open(pathname.c_str(),
           O_WRONLY | O_CREAT | O_NOCTTY | O_NONBLOCK,
           0666) < 0) {
    throw doas::IOError("%s: %s", pathname.c_str(), std::strerror(errno));
  }

  if (utimensat(AT_FDCWD, pathname.c_str(), nullptr, 0) != 0) {
    throw doas::IOError("%s: %s", pathname.c_str(), std::strerror(errno));
  }
}

