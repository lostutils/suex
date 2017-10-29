#include <file.h>
#include <sys/stat.h>
#include <exceptions.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <path.h>

using namespace suex;
using namespace suex::utils;

void file::Secure(int fd) {
  // chown root:root
  if (fchown(fd, 0, 0) < 0) {
    throw suex::PermissionError(std::strerror(errno));
  }

  // chmod 440
  if (fchmod(fd, S_IRUSR | S_IRGRP) < 0) {
    throw suex::PermissionError(std::strerror(errno));
  }
}

void file::Secure(const std::string &path) {
  FILE *f = fopen(path.c_str(), "r");

  if (f == nullptr) {
    throw IOError("path '%s' doesn't exist", path.c_str());
  }

  DEFER(fclose(f));
  return Secure(fileno(f));
}

double file::Size(const std::string &path) {
  struct stat st{};
  if (stat(path.c_str(), &st) != 0) {
    throw IOError("could not find the file specified");
  }
  return st.st_size / 1024.0;
}

void file::Remove(const std::string &path, bool silent) {
  if (!path::Exists(path)) {
    return;
  }

  if (remove(path.c_str()) != 0 && !silent) {
    throw suex::IOError("%s: %s", path.c_str(), std::strerror(errno));
  }
}

void file::Clone(const std::string &from, const std::string &to, bool secure) {
  int src_fd = open(from.c_str(), O_RDONLY, 0);
  if (src_fd == -1) {
    throw suex::IOError("can't clone '%s' to '%s': %s",
                        from.c_str(),
                        to.c_str(),
                        std::strerror(errno));
  }
  DEFER(close(src_fd));

  int dst_fd = open(to.c_str(), O_WRONLY | O_TRUNC | O_CREAT);
  if (dst_fd == -1) {
    throw suex::IOError("can't clone '%s' to '%s': %s",
                        from.c_str(),
                        to.c_str(),
                        std::strerror(errno));
  }
  DEFER(close(dst_fd));

  // only secure the file if it should be secured
  if (secure) {
    if (!file::IsSecure(src_fd)) {
      throw PermissionError("can't clone, source is not secure");
    }
    Secure(dst_fd);
  }

  struct stat st{};
  if (fstat(src_fd, &st) < 0) {
    throw suex::IOError("can't clone '%s' to '%s': %s",
                        from.c_str(),
                        to.c_str(),
                        std::strerror(errno));
  }

  if (sendfile(dst_fd, src_fd, nullptr, (size_t) st.st_size) <= 0) {
    throw suex::IOError("%s: %s", to.c_str(), std::strerror(errno));
  }
}

void file::Create(const std::string &path, bool secure) {
  if (utils::path::Exists(path)) {
    throw IOError("file '%s' already exists", path.c_str());
  }

  FILE *f = fopen(path.c_str(), "w");
  if (f == nullptr) {
    throw IOError("error when opening '%s' for writing", path.c_str());
  }
  DEFER(fclose(f));

  file::Buffer buff(fileno(f), std::ios::out);
  std::ostream os(&buff);
  os << "";

  if (secure) {
    Secure(fileno(f));
  }

}
bool ::suex::file::IsSecure(int fd) {
  struct stat st{};
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

