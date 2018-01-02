#pragma once
#include <ext/stdio_filebuf.h>
#include <string>

namespace suex::file {

typedef __gnu_cxx::stdio_filebuf<char> Buffer;

double Size(int fd);

bool Remove(const std::string &path, bool silent = false);

bool IsSecure(const std::string &path);

bool IsSecure(int fd);

void Secure(int fd);

void Clone(int src_fd, int dst_fd, bool secure = false);

void Create(const std::string &path, bool secure = false);
}
