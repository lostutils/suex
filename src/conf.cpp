#include <logger.h>
#include <conf.h>
#include <path.h>

void Permissions::ValidatePermissions(const std::string &path) const {
  struct stat fstat{};
  stat(path.c_str(), &fstat);

  // config file can only have read permissions for user and group
  if (PermissionBits(fstat) != 440) {
    std::stringstream ss;
    ss << "invalid permission bits: " << PermissionBits(fstat);
    throw std::runtime_error(ss.str());
  }

  // config file has to be owned by root:root
  if (fstat.st_uid != 0 || fstat.st_gid != 0) {
    std::stringstream ss;
    ss << "invalid file owner: " << User(fstat.st_uid).Name() << ":"
       << Group(fstat.st_gid).Name();
    throw std::runtime_error(ss.str());
  }
}

void Permissions::Create(const std::string &path) const {
  std::fstream fs;
  fs.open(path, std::ios::out);

  // chmod 440
  if (chmod(path.c_str(), S_IRUSR | S_IRGRP) < 0) {
    throw std::runtime_error(std::strerror(errno));
  }

  // chown root:root
  if (chown(path.c_str(), 0, 0) < 0) {
    throw std::runtime_error(std::strerror(errno));
  }
  fs.close();
}

bool Permissions::Exists(const std::string &path) const {
  std::ifstream f(path);
  bool exists = f.good();
  f.close();
  return exists;
}

Permissions::Permissions(const std::string &path) {
  // create the file if it doesn't exist,
  // and set the right ownership and permission bits.
  if (!Exists(path)) {
    Create(path);
  }

  // check that the configurations file has the right
  // ownership and permissions
  ValidatePermissions(path);

  // parse each line in the configuration file
  std::ifstream f(path);
  std::string line;
  while (std::getline(f, line)) {
    Parse(line);
  }

  // TODO: RAII
  f.close();
}

std::vector<User> &AddUsers(const std::string &user, std::vector<User> &users) {
  if (user[0] != '%') {
    users.emplace_back(User(user));
    return users;
  }

  // load the group members and add each one
  struct group *gr = getgrnam(user.substr(1, user.npos).c_str());

  if (gr == nullptr) {
    throw std::runtime_error("origin group doesn't exist");
  }

  for (auto it = gr->gr_mem; (*it) != nullptr; it++) {
    users.emplace_back(User(*it));
  }

  return users;
}

void Permissions::PopulatePermissions(const std::smatch &matches) {

  // <user-or-group> -> <dest-user>:<dest-group> ::
  // <path-to-executable-and-args>
  std::vector<User> users;

  // first match is a user or group this line refers to
  // a string that starts with a '%' is a group (like in /etc/sudoers)
  for (User &user : AddUsers(matches[1], users)) {
    if (!user.Exists()) {
      std::stringstream ss;
      throw std::runtime_error("origin user doesn't exist");
    }
  }

  // extract the destination user
  User as_user = User(matches[2]);
  if (!as_user.Exists()) {
    throw std::runtime_error("dest user doesn't exist");
  }

  // extract the destination group
  Group as_group = Group(matches[4], as_user);
  if (!as_group.Exists()) {
    throw std::runtime_error("dest group doesn't exist");
  }

  // extract the executable path.
  // don't try to locate the path in $PATH

  std::string cmd = GetPath(matches[5], false);
  std::string args = matches[7];

  // if no args are passed, the user can execute *any* args
  // we remove single quotes because these don't actually exists,
  // the shell concatenates single-quoted-wrapped strings

  if (!args.empty()) {
    // the regex is reversed because c++11 doesn't support negative lookbehind.
    // instead, the regex has been reversed to look ahead.
    // this whole thing isn't too costly because the lines are short.
    std::reverse(args.begin(), args.end());
    args = std::regex_replace(args, quote_re_, "");
    std::reverse(args.begin(), args.end());
  }

  cmd += args.empty() ? ".*" : "\\s+" + args;

  logger::debug << "command is: " << cmd << std::endl;
  std::regex cmd_re = std::regex(cmd);

  // populate the permissions vector
  for (User &user : users) {
    perms_.emplace_back(ExecutablePermissions(user, as_user, as_group, cmd_re));
  }
}

void Permissions::Parse(const std::string &line) {

  std::smatch matches;
  //  a comment, no need to parse
  if (std::regex_match(line, matches, comment_re_)) {
    return;
  }

  //  an empty line, no need to parse
  if (std::regex_match(line, matches, empty_re_)) {
    return;
  }

  logger::debug << "parsing line: " << line << std::endl;
  try {
    if (!std::regex_search(line, matches, line_re_)) {
      throw std::runtime_error("couldn't parse line");
    }
    PopulatePermissions(matches);

  } catch (std::exception &e) {
    logger::error << "config error, skipping - " << e.what() << " [" << line << "]" << std::endl;
  }
}
const ExecutablePermissions *Permissions::Get(const User &user, const Group &group, char *const *cmdargv)const {
  std::string cmd = std::string(*cmdargv);
  std::string cmdtxt{CommandArgsText(cmdargv)};
  auto it = perms_.cbegin();
  for (it; it != perms_.cend(); ++it) {
    if (it->CanExecute(user, group, cmdtxt)) {
      return &*it;
    }
  }
  return nullptr;
}

bool ExecutablePermissions::CanExecute(const User &user, const Group &group, const std::string &cmd)const {
  if (Me().Id() != getuid()) {
    return false;
  }

  if (AsUser().Id() != user.Id()) {
    return false;
  }

  if (AsGroup().Id() != group.Id()) {
    return false;
  }

  std::smatch matches;
  return std::regex_match(cmd, matches, cmd_re_);
}
