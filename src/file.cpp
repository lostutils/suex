#include <exceptions.h>
#include <file.h>
#include <path.h>
#include <sys/sendfile.h>
#include <cstring>

void suex::file::Secure(int fd) {
  // chown root:root
  if (fchown(fd, 0, 0) < 0) {
    throw suex::PermissionError(std::strerror(errno));
  }

  // chmod 440
  if (fchmod(fd, S_IRUSR | S_IRGRP) < 0) {
    throw suex::PermissionError(std::strerror(errno));
  }
}

double suex::file::Size(int fd) {
  struct stat st {
    0
  };
  if (fstat(fd, &st) != 0) {
    throw IOError("could not find the file specified");
  }
  return st.st_size / 1024.0;
}

bool suex::file::Remove(const std::string &path, bool silent) {
  if (!utils::path::Exists(path)) {
    return false;
  }

  if (remove(path.c_str()) == 0) {
    return true;
  }

  if (silent) {
    return false;
  }

  throw suex::IOError("%s: %s", path.c_str(), std::strerror(errno));
}

void suex::file::Clone(int src_fd, int dst_fd, bool secure) {
  // only secure the file if it should be secured
  if (secure) {
    if (!file::IsSecure(src_fd)) {
      throw PermissionError("can't clone, source is not secure");
    }
    Secure(dst_fd);
  }

  struct stat st {
    0
  };
  if (fstat(src_fd, &st) < 0) {
    throw suex::IOError("can't clone src to dst: %s", std::strerror(errno));
  }

  if (sendfile(dst_fd, src_fd, nullptr, static_cast<size_t>(st.st_size)) <= 0) {
    throw suex::IOError("can't source src to dst. sendfile() failed: %s",
                        std::strerror(errno));
  }
}

void suex::file::Create(const std::string &path, bool secure) {
  if (utils::path::Exists(path)) {
    throw IOError("file '%s' already exists", path.c_str());
  }

  FILE *f = fopen(path.c_str(), "w");
  if (f == nullptr) {
    throw IOError("error when opening '%s' for writing", path.c_str());
  }
  DEFER(fclose(f));

  suex::file::Buffer buff(fileno(f), std::ios::out);
  std::ostream os(&buff);
  os << "";

  if (secure) {
    Secure(fileno(f));
  }
}
bool ::suex::file::IsSecure(int fd) {
  struct stat st {
    0
  };
  if (fstat(fd, &st) != 0) {
    throw IOError("could not find the file specified");
  }

  int user = (st.st_mode & S_IRWXU) >> 6;
  int group = (st.st_mode & S_IRWXG) >> 3;
  int others = st.st_mode & S_IRWXO;
  int bits = (user * 100) + (group * 10) + others;

  if (bits != 440) {
    return false;
  }

  // owner should be root:root
  return st.st_uid == 0 && st.st_gid == 0;
}

bool ::suex::file::IsSecure(const std::string &path) {
  FILE *f = fopen(path.c_str(), "r");
  if (f == nullptr) {
    throw IOError("could not find the file specified");
  }
  DEFER(fclose(f));
  return IsSecure(fileno(f));
}
