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
  for (int lineno = 1; std::getline(f, line); lineno++ ) {
    Parse(lineno, line);
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
  std::smatch matches;
  if (!std::regex_search(line, matches, bsd_re_)) {
    logger::debug << "couldn't parse: " << line << std::endl;
    throw std::runtime_error("couldn't parse line");
  }
  // <user-or-group> -> <dest-user>:<dest-group> ::
  // <path-to-executable-and-args>
  std::vector<User> users;

  std::smatch opt_matches;
  bool deny = matches[1] == "deny";

  bool nopass{false};
  bool keepenv{false};
  bool persist{false};

  const std::string opts{matches[3].str()};
  for (auto it = opts.cbegin(); std::regex_search(it, opts.cend(), opt_matches, opt_re_);
       it += opt_matches.position() + opt_matches.length()) {

    std::string opt_match{opt_matches.str()};
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
  std::string cmd_binary{matches[8].str()};
  if (cmd_binary.empty() && nopass && as_user.Id() == 0) {
    throw std::runtime_error("cmd doesn't exist but nopass is set");
  }

  std::string cmd_re = cmd_binary.empty() ? ".+" : GetPath(cmd_binary, true);

  // parse the args
  std::string cmd_args{matches[10].str()};
  if (!cmd_args.empty()) {
    // the regex is reversed because c++11 doesn't support negative lookbehind.
    // instead, the regex has been reversed to look ahead.
    // this whole thing isn't too costly because the lines are short.
    std::reverse(cmd_args.begin(), cmd_args.end());
    cmd_args = std::regex_replace(cmd_args, quote_re_, "");
    std::reverse(cmd_args.begin(), cmd_args.end());

    cmd_re += "\\s+" + cmd_args;
  }

  // populate the permissions vector
  for (User &user : users) {
    auto perm = ExecutablePermissions(user,
                                      as_user,
                                      deny,
                                      keepenv,
                                      nopass,
                                      persist,
                                      cmd_re);
    perms_.emplace_back(perm);
    logger::debug << "perm added: " << perm.ToString() << std::endl;
  }
}

void Permissions::Parse(int lineno, const std::string &line) {
  logger::debug << "parsing line " << lineno << ": '" << line << "'" << std::endl;

  std::smatch matches;
  //  a comment, no need to parse
  if (std::regex_match(line, matches, comment_re_)) {
    logger::debug << "line " << lineno << " is a comment, skipping." << std::endl;
    return;
  }

  //  an empty line, no need to parse
  if (std::regex_match(line, matches, empty_re_)) {
    logger::debug << "line " << lineno << " is empty, skipping." << std::endl;
    return;
  }

  try {
    ParseLine(line);
    logger::debug << "line " << lineno << " parsed successfully" << std::endl;
  } catch (std::exception &e) {
    logger::error << "skipping line " << lineno << ": " << e.what() << std::endl;
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
  logger::debug << (matched ? "Y" : "N") << " " << cmd_re_txt_ << " ~= " << cmd << std::endl;
  return matched;
}
std::string ExecutablePermissions::ToString() const {
  std::stringstream ss;
  ss << "user: " << user_.Name() << " | " <<
     "as-user: " << as_user_.Name() << " | " <<
     "deny: " << deny_ << " | " <<
     "nopass: " << nopass_ << " | " <<
     "keepenv: " << keepenv_ << " | " <<
     "cmd-regex: " << cmd_re_txt_;
  return ss.str();
}
