#pragma once

#include <memory>

// https://stackoverflow.com/a/26221725/4579708
template <typename... Args>
std::string Sprintf(const std::string &format, Args &&... args) {
  // Extra space for '\0'
  size_t size = (size_t)snprintf(nullptr, 0, format.c_str(), args...) + 1;
  std::unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), size, format.c_str(), args...);
  // We don't want the '\0' inside
  return std::string(buf.get(), buf.get() + size - 1);
}
