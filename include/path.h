#pragma once

#include <string>

std::string getpath(const std::string &path, bool searchInPath);

const std::string realpath(std::string &path);

