#pragma once
#include <string>
#include <ext/stdio_filebuf.h>

namespace suex::file {

typedef __gnu_cxx::stdio_filebuf<char> Buffer;

double Size(const std::string &path);

void Remove(const std::string &path, bool silent = false);

bool IsSecure(const std::string &path);

void Secure(const std::string &path);

void Secure(int fd);

void Clone(const std::string &from, const std::string &to, bool secure = false);

void Create(const std::string &path, bool secure = false);

int PermissionBits(const std::string& path);
}

