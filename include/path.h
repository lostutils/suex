#pragma once

#include <string>

const std::string GetPath(const std::string &path, bool searchInPath);

const std::string RealPath(const std::string &path);

const std::string LocatePath(const std::string &path, bool searchInPath);

