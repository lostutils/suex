#include <climits>
#include <exceptions.hpp>
#include <file.hpp>
#include <gsl/gsl>
#include <logger.hpp>
#include <sstream>

const std::string path::Locate(const std::string &path, bool searchInPath) {
  if (path.empty()) {
    throw suex::IOError("path '%s' is empty", path.c_str());
  }

  file::stat_t st{0};
  if (stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
    return path;
  }

  std::string name(basename(path.c_str()));
  if (env::Contains("PATH") && searchInPath) {
    std::istringstream iss(env::Get("PATH"));
    std::string dir;
    while (getline(iss, dir, ':')) {
      std::string fullpath{Sprintf("%s/%s", dir.c_str(), name.c_str())};
      if (stat(fullpath.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
        return fullpath;
      }
    }
  }

  throw suex::IOError("path '%s' doesn't exist", path.c_str());
}

bool path::Exists(const std::string &path) {
  file::stat_t status{0};
  return stat(path.c_str(), &status) == 0;
}
const std::string path::Readlink(int fd) {
  std::string path{GetPath(fd)};
  char buff[PATH_MAX];
  auto buff_view{gsl::make_span(buff)};
  ssize_t read = readlink(path.c_str(), buff_view.data(), PATH_MAX - 1);
  if (read < 0) {
    throw suex::IOError("couldn't readlink '%s': %s", path.c_str(),
                        strerror(errno));
  }

  buff_view.at(read) = '\0';
  return buff_view.data();
}
const std::string path::GetPath(int fd) {
  return Sprintf("/proc/%d/fd/%d", getpid(), fd);
}
