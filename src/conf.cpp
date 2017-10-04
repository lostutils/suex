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
  if (user[0] != ':') {
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

void Permissions::ParseLine(const std::string &line) {

  logger::debug << "parsing: " << line << std::endl;

  std::smatch matches;
  if (!std::regex_search(line, matches, bsd_re_)) {
    logger::debug << "couldn't parse: " << line << std::endl;
    throw std::runtime_error("couldn't parse line");
  }
  // <user-or-group> -> <dest-user>:<dest-group> ::
  // <path-to-executable-and-args>
  std::vector<User> users;

  std::smatch opt_matches;
  const std::string m{matches[3].str()};
  bool deny = matches[1] == "deny";

  bool nopass{false};
  bool keepenv{false};
  bool persist{false};

  if (std::regex_search(m, opt_matches, opt_re_)) {
    for (const auto &opt_match : opt_matches) {
      if (opt_match == "nopass") {
        nopass = true;
      }
      if (opt_match == "keepenv") {
        keepenv = true;
      }
      if (opt_match == "persist") {
        persist = true;
      }
    }
  }

  // first match is a user or group this line refers to
  // a string that starts with a '%' is a group (like in /etc/sudoers)
  for (User &user : AddUsers(matches[4], users)) {
    if (!user.Exists()) {
      std::stringstream ss;
      throw std::runtime_error("origin user doesn't exist");
    }
  }

  // extract the destination user
  User as_user = User(matches[6]);
  if (!as_user.Exists()) {
    throw std::runtime_error("destination user doesn't exist");
  }


  // disallow running any cmd as root with nopass
  std::string cmd_binary { matches[11].str() };
  if (cmd_binary.empty() && nopass && as_user.Id() == 0) {
    throw std::runtime_error("cmd doesn't exist but nopass is set");
  }

  std::string cmd_re = cmd_binary.empty() ? ".+" : GetPath(cmd_binary, true);
  if (!cmd_binary.empty()) {
    std::string cmd_args {matches[13].str()};

    // if no args are passed, the user can execute *any* args
    // we remove single quotes because these don't actually exists,
    // the shell concatenates single-quoted-wrapped strings

    if (!cmd_args.empty()) {
      // the regex is reversed because c++11 doesn't support negative lookbehind.
      // instead, the regex has been reversed to look ahead.
      // this whole thing isn't too costly because the lines are short.
      std::reverse(cmd_args.begin(), cmd_args.end());
      cmd_args = std::regex_replace(cmd_args, quote_re_, "");
      std::reverse(cmd_args.begin(), cmd_args.end());
    }

    cmd_re += cmd_args.empty() ? ".*" : "\\s+" + cmd_args;
  }

  // populate the permissions vector
  for (User &user : users) {
    perms_.emplace_back(ExecutablePermissions(user,
                                              as_user,
                                              deny,
                                              keepenv,
                                              nopass,
                                              persist,
                                              cmd_re,
                                              line));
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

  try {
    ParseLine(line);
  } catch (std::exception &e) {
    logger::error << "config error, skipping - " << e.what() << " [" << line << "]" << std::endl;
  }
}
const ExecutablePermissions *Permissions::Get(const User &user, char *const *cmdargv) const {
  std::string cmd = std::string(*cmdargv);
  std::string cmdtxt{CommandArgsText(cmdargv)};
  auto it = perms_.cbegin();
  for (it; it != perms_.cend(); ++it) {
    if (it->CanExecute(user, cmdtxt)) {
      return &*it;
    }
  }
  return nullptr;
}

bool ExecutablePermissions::CanExecute(const User &user, const std::string &cmd) const {
  if (Me().Id() != getuid()) {
    return false;
  }

  if (AsUser().Id() != user.Id()) {
    return false;
  }

  std::smatch matches;
  bool matched{std::regex_match(cmd, matches, cmd_re_)};
  logger::debug << (matched ? "Y" : "N") << " " << raw_txt_ << " ~= " << cmd << std::endl;
  return matched;
}
