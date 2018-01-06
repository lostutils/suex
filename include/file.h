#pragma once
#include <ext/stdio_filebuf.h>
#include <string>

namespace suex::file {

typedef __gnu_cxx::stdio_filebuf<char> Buffer;

double Size(int fd);

bool Remove(const std::string &path, bool silent = false);

bool IsSecure(int fd);

void Clone(int src_fd, int dst_fd, mode_t mode);
}
