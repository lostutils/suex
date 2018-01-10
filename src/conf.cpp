#include <conf.h>
#include <exceptions.h>
#include <fcntl.h>
#include <file.h>
#include <glob.h>
#include <logger.h>
#include <rx.h>
#include <climits>
#include <gsl/gsl>
#include <sstream>

using suex::permissions::Entity;
using suex::permissions::Permissions;
using suex::permissions::User;
using suex::permissions::Group;
using suex::permissions::Group;

permissions::Permissions::Permissions(Permissions &other) noexcept
    : auth_style_{std::move(other.auth_style_)},
      perms_{std::move(other.perms_)},
      fd_{other.fd_},
      auto_close_{other.auto_close_} {
  other.perms_ = std::vector<Entity>();
  other.fd_ = -1;
}
permissions::Permissions::~Permissions() {
  if (fd_ != -1 && auto_close_) {
    file::Close(fd_);
  }
}

void ProcessEnv(const std::string &txt, Entity::EnvToAdd *upsert,
                Entity::EnvToRemove *remove) {
  uint64_t openTokenIdx = txt.find_first_of('{');
  uint64_t closeTokenIdx = txt.find_last_of('}');

  std::istringstream iss{
      txt.substr(openTokenIdx + 1, closeTokenIdx - openTokenIdx - 1)};
  while (iss) {
    std::string token;
    iss >> token;
    if (token.empty()) {
      continue;
    }
    // remove: token starts with '-'
    if (token[0] == '-') {
      remove->emplace(token.substr(1));
      continue;
    }

    uint64_t sepIdx = token.find_first_of('=');

    if (sepIdx == token.npos) {
      upsert->emplace(token, env::Get(token));
      continue;
    }

    std::string key{token.substr(0, sepIdx)};
    std::string val{token.substr(sepIdx + 1)};

    if (val[0] == '$') {
      std::string realkey{val.substr(1)};
      if (!env::Contains(realkey)) {
        continue;
      }
      val = env::Get(realkey);
    }

    upsert->emplace(key, val);
  }
}

const std::vector<User> &GetUsers(const std::string &user,
                                  std::vector<User> *users) {
  if (user[0] != ':') {
    users->emplace_back(User(user));
    return *users;
  }

  Group grp{user.substr(1, user.npos)};
  if (!grp.Exists()) {
    throw suex::PermissionError("group %s doesn't exist", grp.Name().c_str());
  }

  for (auto mem : grp) {
    users->emplace_back(mem);
  }

  return *users;
}

bool IsExecutable(const std::string &path) {
  struct stat st {
    0
  };
  if (stat(path.c_str(), &st) < 0) {
    throw suex::IOError("couldn't get executable stat");
  }
  // ignore non executables
  return (st.st_mode & S_IEXEC) == S_IEXEC && S_ISREG(st.st_mode);
}

const std::vector<std::string> &GetExecutables(const std::string &glob_pattern,
                                               std::vector<std::string> *vec) {
  glob_t globbuf{0};
  if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) != 0) {
    logger::warning() << "there are no executables at " << glob_pattern
                      << std::endl;
    return *vec;
  }
  DEFER(globfree(&globbuf));

  auto paths = gsl::make_span(globbuf.gl_pathv, globbuf.gl_pathc);

  for (std::string path : paths) {
    if (IsExecutable(path)) {
      vec->emplace_back(suex::utils::path::Locate(path, false));
    }
  }

  if (vec->size() == 1 && !IsExecutable(vec->front())) {
    throw suex::PermissionError("%s is not executable (missing +x flag)",
                                vec->front().c_str());
  }

  return *vec;
}

std::string ParseCommand(const std::string &cmd, const std::string &args) {
  if (args.empty()) {
    return cmd;
  }
  std::string whitespace{R"(\s)"};
  std::ostringstream ss;
  ss << cmd.c_str() << whitespace.c_str();
  bool escaped = false;
  for (const auto &c : args) {
    // remove quotes from non-escaped sequences
    if (!escaped && (c == '\'' || c == '"')) {
      continue;
    }
    if (c == ' ') {
      ss << whitespace.c_str();
      continue;
    }

    escaped = c == '\\';
    ss << c;
  }
  return ss.str();
};

void ParseOptions(const std::string &options, bool *nopass, bool *keepenv,
                  bool *persist, Entity::EnvToAdd *env_to_add,
                  Entity::EnvToRemove *env_to_remove) {
  if (options.empty()) {
    return;
  }
  std::string opt_match{};
  re2::StringPiece sp{options};
  while (re2::RE2::FindAndConsume(&sp, permissions::PermissionsOptionsRegex(),
                                  &opt_match)) {
    if (opt_match == "nopass") {
      *nopass = true;
    }
    if (opt_match == "keepenv") {
      *keepenv = true;
    }
    if (opt_match == "persist") {
      *persist = true;
    }
    if (opt_match.find("setenv") == 0) {
      ProcessEnv(opt_match, env_to_add, env_to_remove);
    }
  }
}

void permissions::Permissions::Parse(
    const struct Line &line, std::function<void(const Entity &)> &&callback) {
  logger::debug() << "parsing line " << line.lineno << ": '" << line.txt << "'"
                  << std::endl;

  //  a comment, no need to parse
  if (re2::RE2::FullMatch(line.txt, CommentLineRegex())) {
    logger::debug() << "line " << line.lineno << " is a comment, skipping."
                    << std::endl;
    return;
  }

  //  an empty line, no need to parse
  if (re2::RE2::FullMatch(line.txt, EmptyLineRegex())) {
    logger::debug() << "line " << line.lineno << " is empty, skipping."
                    << std::endl;
    return;
  }

  utils::rx::Matches m;
  if (!utils::rx::NamedFullMatch(PermissionLineRegex(), line.txt, &m)) {
    logger::debug() << "couldn't parse: " << line.txt << std::endl;
    throw ConfigError("line is invalid: '%s'", line.txt.c_str());
  }

  bool nopass{false}, keepenv{false}, persist{false};
  Entity::EnvToRemove env_to_remove;
  Entity::EnvToAdd env_to_add;
  ParseOptions(m["options"], &nopass, &keepenv, &persist, &env_to_add,
               &env_to_remove);

  bool deny = m["type"] == "deny";

  // extract the destination user
  User as_user = User(m["as"]);
  if (!as_user.Exists()) {
    throw suex::PermissionError("destination user '%s' doesn't exist",
                                as_user.Name().c_str());
  }

  // disallow running any cmd as root with nopass
  if (m["cmd"].empty() && nopass && as_user.Id() == 0) {
    throw suex::PermissionError("cmd doesn't exist but nopass is set");
  }

  std::vector<std::string> binaries;
  for (const auto &exe : GetExecutables(m["cmd"], &binaries)) {
    // populate the permissions vector
    std::vector<User> users;
    for (const User &user : GetUsers(m["user"], &users)) {
      if (!user.Exists()) {
        throw suex::PermissionError("user '%s' doesn't exist",
                                    user.Name().c_str());
      }

      // parse the args
      std::string cmd_re{ParseCommand(exe, m["args"])};
      callback(permissions::Entity(user, as_user, deny, keepenv, nopass,
                                   persist, env_to_add, env_to_remove, cmd_re));
    }
  }
  logger::debug() << "line " << line.lineno << " parsed successfully"
                  << std::endl;
}

const Entity *Permissions::Get(const permissions::User &user,
                               const std::vector<char *> &cmdargv) const {
  std::string cmd = std::string(*cmdargv.data());
  std::string cmdtxt{utils::CommandArgsText(cmdargv)};

  // take the latest one you find (like the original suex)
  const Entity *perm = nullptr;
  for (const permissions::Entity &p : perms_) {
    if (p.CanExecute(user, cmdtxt)) {
      perm = &p;
    }
  }

  return perm;
}

Permissions::Permissions(int fd, std::string auth_style)
    : auth_style_{std::move(auth_style)}, fd_{fd}, auto_close_{false} {}

Permissions::Permissions(const std::string &path, std::string auth_style)
    : auth_style_{std::move(auth_style)},
      fd_{file::Open(path, O_CREAT | O_RDONLY, S_IRUSR | S_IRGRP)},
      auto_close_{true} {}

Permissions &Permissions::Load() {
  std::string path{utils::path::Readlink(fd_)};

  struct flock write_lock = {0};
  if (path == PATH_CONFIG) {
    write_lock.l_type = F_RDLCK;
    logger::debug() << "acquiring lock on " << path << std::endl;
    if (fcntl(fd_, F_OFD_SETLKW, &write_lock) < 0) {
      throw suex::IOError("Error when locking configuration: %s",
                          strerror(errno));
    }
  }

  DEFER(if (path == PATH_CONFIG) {
    write_lock.l_type = F_UNLCK;
    fcntl(fd_, F_OFD_SETLKW, &write_lock);
  });

  logger::debug() << "parsing '" << path << "' (fd " << fd_ << ")" << std::endl;
  if (path == PATH_CONFIG && !file::IsSecure(fd_)) {
    throw suex::PermissionError("'%s' is not secure", path.c_str());
  }

  if (file::Size(fd_) > MAX_FILE_SIZE) {
    throw suex::PermissionError("'%s' size is %ld, which is not supported",
                                path.c_str(), file::Size(fd_));
  }

  char *line = nullptr;

  // fdopen should have seeked to the beginning of the file
  // but in practice, it doesn't always work.
  file::Seek(fd_, 0, SEEK_SET);
  FILE *f{fdopen(fd_, "r")};
  if (f == nullptr) {
    throw suex::IOError("error opening '%d' for reading: %s", fd_,
                        std::strerror(errno));
  }
  for (int lineno = 1; file::ReadLine(f, &line); lineno++) {
    try {
      Line meta{.lineno = lineno, .txt = line};
      Parse(meta, [&](const Entity &e) { perms_.emplace_back(e); });

    } catch (SuExError &e) {
      // configuration is invalid.
      // clear all loaded permissions and log
      perms_.clear();
      logger::error() << e.what() << std::endl;
      return *this;
    }
  }

  // if the user is privileged, add an "all rule" to the
  // beginning of the permissions vector
  if (Privileged()) {
    bool deny{false}, keepenv{true}, nopass{false}, persist(true);
    auto p = permissions::Entity(RunningUser(), RootUser(), deny, keepenv,
                                 nopass, persist, ".+");
    perms_.emplace(perms_.begin(), p);
  }

  return *this;
}
const re2::RE2 &permissions::PermissionsOptionsRegex() {
  static const re2::RE2 re{R"((nopass|persist|keepenv|setenv\s\{.*\}))"};
  if (!re.ok()) {
    throw std::runtime_error("permissions options regex failed to compile");
  }
  return re;
}
const re2::RE2 &permissions::PermissionLineRegex() {
  static const re2::RE2 re{
      R"(^(?P<type>permit|deny)\s+((?P<options>.*)\s+)?(?P<user>(:)?[a-z_][a-z0-9_-]*[$]?)\s+as\s+(?P<as>[a-z_][a-z0-9_-]*[$]?)\s+cmd\s+(?P<cmd>[^\s]+)(\s+args\s+((?P<args>[^\s].*[^\s])[\s]*))?\s*$)"};
  if (!re.ok()) {
    throw std::runtime_error("permissions regex failed to compile");
  }
  return re;
}
const re2::RE2 &permissions::CommentLineRegex() {
  static const re2::RE2 re{R"(^[\t|\s]*#.*)"};
  if (!re.ok()) {
    throw std::runtime_error("comment regex failed to compile");
  }
  return re;
}
const re2::RE2 &permissions::EmptyLineRegex() {
  static const re2::RE2 re{R"(^[\t|\s]*)"};
  if (!re.ok()) {
    throw std::runtime_error("empty line regex failed to compile");
  }
  return re;
}
