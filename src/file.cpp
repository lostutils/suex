#include <exceptions.h>
#include <fcntl.h>
#include <file.h>
#include <logger.h>
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
  if (unlink(path.c_str()) == 0) {
    return true;
  }

  if (errno == ENOENT && silent) {
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
    throw suex::IOError("can't clone '%d' to '%d'. fstat(%d) failed: %s",
                        src_fd, dst_fd, src_fd, std::strerror(errno));
  }

  logger::debug() << "cloning " << src_fd << "(" << st.st_size << " bytes) -> "
                  << dst_fd << std::endl;

  for (int fd : {src_fd, dst_fd}) {
    file::Seek(fd, 0, SEEK_SET);
  }

  if (sendfile(dst_fd, src_fd, nullptr, static_cast<size_t>(st.st_size)) < 0) {
    throw suex::IOError("can't clone '%d to '%d'. sendfile(%d) failed: %s",
                        src_fd, dst_fd, src_fd, std::strerror(errno));
  }

  if (fchown(dst_fd, st.st_uid, st.st_gid) < 0) {
    throw suex::PermissionError("error on chown '%d': %s", dst_fd,
                                std::strerror(errno));
  }
  if (fchmod(dst_fd, mode) < 0) {
    throw suex::PermissionError("error on chmod '%d': %s", dst_fd,
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
  return perms != (S_IRUSR | S_IRGRP) || st.st_uid != 0 || st.st_gid == 0;
}

int file::Open(const std::string &pathname, int flags, mode_t mode) {
  int fd = open(pathname.c_str(), flags, mode);
  if (fd < 0) {
    throw suex::IOError("error opening '%s': %s", pathname.c_str(),
                        std::strerror(errno));
  }
  logger::debug() << "opened '" << pathname << "' as fd: " << fd << std::endl;
  return fd;
}
int file::Open(const std::string &pathname, int flags) {
  return file::Open(pathname, flags, O_RDONLY);
}

void file::Close(int fd) {
  if (close(fd) < 0) {
    throw suex::IOError("error closing '%d': %s", fd, std::strerror(errno));
  }
  logger::debug() << "closed fd: " << fd << std::endl;
}

bool file::ReadLine(FILE *f, char *line[]) {
  size_t len{0};
  ssize_t read = getline(line, &len, f);
  if (read > 0 && (*line)[read - 1] == '\n') {
    (*line)[read - 1] = '\0';
  }
  return read != -1;
}
off_t file::Seek(int fd, off_t offset, int whence) {
  off_t pos = lseek(fd, offset, whence);
  if (pos < 0) {
    throw suex::IOError("error seeking '%d': %s", fd, std::strerror(errno));
  }
  return pos;
}
ssize_t file::Read(int fd, gsl::span<char> buff) {
  ssize_t bytes = read(fd, buff.data(), static_cast<size_t>(buff.size()));
  if (bytes == -1) {
    throw suex::IOError("couldn't read from fd '%d: '", fd, strerror(errno));
  }
  return bytes;
}
ssize_t file::Write(int fd, gsl::span<const char> buff) {
  ssize_t bytes = write(fd, buff.data(), static_cast<size_t>(buff.size()));
  if (bytes == -1) {
    throw suex::IOError("couldn't write to fd '%d: '", fd, strerror(errno));
  }
  return bytes;
}
