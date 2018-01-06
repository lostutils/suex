#include <exceptions.h>
#include <fcntl.h>
#include <file.h>
#include <logger.h>
#include <path.h>
#include <sys/sendfile.h>
#include <cstring>

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

void suex::file::Clone(int src_fd, int dst_fd, mode_t mode) {
  // only secure the file if it should be secured

  struct stat st {
    0
  };
  if (fstat(src_fd, &st) < 0) {
    throw suex::IOError("can't clone src to dst: %s", std::strerror(errno));
  }

  logger::debug() << "cloning " << src_fd << "(" << st.st_size << " bytes) -> "
                  << dst_fd << std::endl;

  if (sendfile(dst_fd, src_fd, nullptr, static_cast<size_t>(st.st_size)) < 0) {
    throw suex::IOError("can't clone src to dst. splice() failed: %d, %s",
                        errno, std::strerror(errno));
  }

  if (fchown(dst_fd, st.st_uid, st.st_gid) < 0) {
    throw suex::PermissionError("error on cloning chown: %s",
                                std::strerror(errno));
  }
  if (fchmod(dst_fd, mode) < 0) {
    throw suex::PermissionError("error on cloning chmod: %s",
                                std::strerror(errno));
  }
}

bool ::suex::file::IsSecure(int fd) {
  struct stat st {
    0
  };

  if (fstat(fd, &st) != 0) {
    throw IOError("could not find the file specified");
  }

  int perms = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);

  if (perms != (S_IRUSR | S_IRGRP)) {
    return false;
  }

  // owner should be root:root
  return st.st_uid == 0 && st.st_gid == 0;
}
