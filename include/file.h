#pragma once
#include <gsl/gsl>
#include <string>

namespace suex::file {

double Size(int fd);

bool Remove(const std::string &path, bool silent = false);

bool IsSecure(int fd);

int Open(const std::string &pathname, int flags);

int Open(const std::string &pathname, int flags, mode_t mode);

void Close(int fd);

void Clone(int src_fd, int dst_fd, mode_t mode);

off_t Seek(int fd, off_t offset, int whence);

ssize_t Read(int fd, gsl::span<char> buff);

ssize_t Write(int fd, gsl::span<const char> buff);

bool ReadLine(FILE *f, char *line[]);
}
