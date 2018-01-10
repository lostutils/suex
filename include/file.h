#pragma once
#include <exceptions.h>
#include <fcntl.h>
#include <path.h>
#include <sys/stat.h>
#include <gsl/gsl>
#include <string>

namespace suex::file {

struct line_t {
  std::string txt;
  int lineno;
};

typedef struct stat stat_t;

class File {
 public:
  explicit File(int fd);

  template <typename... Args>
  explicit File(const std::string &path, int flags, Args &&... args) {
    fd_ = open(path.c_str(), flags, args...);
    if (fd_ < 0) {
      throw suex::IOError("error opening '%s': %s", path.c_str(),
                          std::strerror(errno));
    }
    path_ = utils::path::Readlink(fd_);
    internal_path_ = utils::path::GetPath(fd_);
  }

  File(const File &) = delete;

  File(File &other) noexcept;

  ~File();

  void operator=(const File &) = delete;

  off_t Size() const;

  void SuppressClose();

  mode_t Mode() const;

  bool Remove(bool silent = false);

  bool IsSecure() const;

  off_t Tell() const;

  void Clone(File &other, mode_t mode) const;

  off_t Seek(off_t offset, int whence) const;

  const std::string &Path() const;

  const std::string &DescriptorPath() const;

  ssize_t Read(gsl::span<char> buff) const;

  ssize_t Write(gsl::span<const char> buff) const;

  std::string String() const;

  bool Valid() const;

  void ReadLine(std::function<void(const line_t &)> &&callback);

  template <typename... Args>
  int Control(int cmd, Args &&... args) const {
    int ret = fcntl(fd_, cmd, args...);
    if (ret < 0) {
      throw suex::IOError("fcntl(%d) failed", fd_, strerror(errno));
    }
    return ret;
  }

 private:
  int fd_{-1};
  std::string path_{};
  std::string internal_path_{};
  bool auto_close_{true};

  const stat_t Status() const;
  void Invalidate();
  void Close();
};
}
