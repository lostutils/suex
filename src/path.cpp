#include <exceptions.h>
#include <logger.h>
#include <gsl/gsl>
#include <sstream>

const std::string utils::path::Locate(const std::string &path,
                                      bool searchInPath) {
  if (path.empty()) {
    throw suex::IOError("path '%s' is empty", path.c_str());
  }

  struct stat st {
    0
  };
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

bool utils::path::Exists(const std::string &path) {
  struct stat fstat {
    0
  };
  return stat(path.c_str(), &fstat) == 0;
}
