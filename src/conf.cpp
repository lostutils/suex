#include <conf.h>
#include <exceptions.h>
#include <file.h>
#include <glob.h>
#include <logger.h>
#include <gsl/gsl>

using suex::permissions::Entity;
using suex::permissions::Permissions;
using suex::permissions::User;
using suex::permissions::Group;
using suex::permissions::Group;

void ProcessEnv(const std::string &txt, Entity::HashTable *upsert,
                Entity::Collection *remove) {
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
  if (user[0] == ':') {
    Group grp{user.substr(1, user.npos)};
    if (!grp.Exists()) {
      throw suex::PermissionError("group %s doesn't exist", grp.Name().c_str());
    }
    for (auto mem : grp) {
      users->emplace_back(mem);
    }
  } else {
    users->emplace_back(User(user));
  }
  return *users;
}

bool IsExecutable(const std::string &path) {
  struct stat st {};
  if (stat(path.c_str(), &st) < 0) {
    throw suex::IOError("couldn't get executable stat");
  }
  // ignore non executables
  return (st.st_mode & S_IEXEC) == S_IEXEC && S_ISREG(st.st_mode);
}

const std::vector<std::string> &GetExecutables(const std::string &glob_pattern,
                                               std::vector<std::string> *vec) {
  glob_t globbuf{};
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

void Permissions::ParseLine(int lineno, const std::string &line,
                            bool only_user) {
  logger::debug() << "parsing line " << lineno << ": '" << line << "'"
                  << std::endl;

  std::smatch matches;
  //  a comment, no need to parse
  if (std::regex_match(line, matches, CommentLineRegex())) {
    logger::debug() << "line " << lineno << " is a comment, skipping."
                    << std::endl;
    return;
  }

  //  an empty line, no need to parse
  if (std::regex_match(line, matches, EmptyLineRegex())) {
    logger::debug() << "line " << lineno << " is empty, skipping." << std::endl;
    return;
  }

  if (!std::regex_search(line, matches, PermissionLineRegex())) {
    logger::debug() << "couldn't parse: " << line << std::endl;
    throw suex::ConfigError("line invalid");
  }

  bool deny = matches[1] == "deny";
  bool nopass{false}, keepenv{false}, persist{false};

  Entity::Collection env_to_remove;
  Entity::HashTable env_to_add;
  const std::string opts{matches[3].str()};
  std::smatch opt_matches;
  for (auto it = opts.cbegin(); std::regex_search(it, opts.cend(), opt_matches,
                                                  PermissionsOptionsRegex());
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
    if (opt_match.find("setenv") == 0) {
      ProcessEnv(opt_match, &env_to_add, &env_to_remove);
    }
  }

  // extract the destination user
  User as_user = User(matches[6]);
  if (!as_user.Exists()) {
    throw suex::PermissionError("destination user '%s' doesn't exist",
                                as_user.Name().c_str());
  }

  // disallow running any cmd as root with nopass
  std::string cmd_binary_{matches[7].str()};
  if (cmd_binary_.empty() && nopass && as_user.Id() == 0) {
    throw suex::PermissionError("cmd doesn't exist but nopass is set");
  }

  std::vector<std::string> binaries;
  for (const auto &exe : GetExecutables(cmd_binary_, &binaries)) {
    // parse the args
    std::string cmd_args{matches[10].str()};
    std::string cmd_re{exe};
    if (!cmd_args.empty()) {
      // the regex is reversed because c++11 doesn't support negative
      // lookbehind.
      // instead, the regex has been reversed to look ahead.
      // this whole thing isn't too costly because the lines are short.
      std::reverse(cmd_args.begin(), cmd_args.end());
      cmd_args = std::regex_replace(cmd_args, QuoteLineRegex(), "");
      std::reverse(cmd_args.begin(), cmd_args.end());

      cmd_re += R"(\s+)" + cmd_args;
    }

    // populate the permissions vector
    std::vector<User> users;
    for (const User &user : GetUsers(matches[4], &users)) {
      if (only_user && user.Id() != RunningUser().Id()) {
        logger::debug() << "skipping user '" << user.Name()
                        << "' - only user mode" << std::endl;
      }

      if (!user.Exists()) {
        throw suex::PermissionError("user '%s' doesn't exist",
                                    user.Name().c_str());
      }

      perms_.emplace_back(permissions::Entity(user, as_user, deny, keepenv,
                                              nopass, persist, env_to_add,
                                              env_to_remove, cmd_re));
    }
  }
  logger::debug() << "line " << lineno << " parsed successfully" << std::endl;
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

bool Permissions::Validate(const std::string &path,
                           const std::string &auth_style) {
  Permissions perms{path, auth_style, false};
  return perms.Size() > 0;
}

Permissions::Permissions(const std::string &path, std::string auth_style,
                         bool only_user)
    : auth_style_{std::move(auth_style)}, secure_{PATH_CONFIG == path} {
  // only secure the main file
  if (!suex::utils::path::Exists(path)) {
    file::Create(path, secure_);
  }
  Parse(path, only_user);
}

bool GetLine(std::istream &is, std::string *line) {
  std::stringstream ss;
  char buff{'\0'};
  while (!is.eof() && ss.tellp() < MAX_LINE) {
    is.read(&buff, 1);
    if (buff == '\n') {
      break;
    }

    ss << buff;
  }

  if (ss.tellp() > MAX_LINE) {
    throw ConfigError("line is too long and will not be parsed");
  }

  *line = ss.str();

  return !is.eof();
}

void Permissions::Parse(const std::string &path, bool only_user) {
  FILE *f = fopen(path.c_str(), "r");

  if (f == nullptr) {
    throw IOError("error when opening '%s' for writing", path.c_str());
  }
  DEFER(fclose(f));

  if (secure_ && !file::IsSecure(fileno(f))) {
    throw suex::PermissionError("'%s' is not secure", path.c_str());
  }

  if (file::Size(fileno(f)) > MAX_FILE_SIZE) {
    throw suex::PermissionError("'%s' size is %ld, which is not supported",
                                path.c_str(), file::Size(path));
  }

  perms_.clear();

  file::Buffer buff(fileno(f), std::ios::in);
  std::istream is(&buff);

  std::string line;
  for (int lineno = 1; GetLine(is, &line); lineno++) {
    try {
      ParseLine(lineno, line, only_user);
    } catch (std::exception &e) {
      logger::error() << e.what() << std::endl;
      perms_.clear();
      return;
    }
  }

  // if the user is privileged, add an "all rule" to the
  // beginning of the permissions vector
  if (Privileged()) {
    auto p = permissions::Entity(RunningUser(), RootUser(), false, true, false,
                                 true, ".+");
    perms_.emplace(perms_.begin(), p);
  }
}
const std::regex & ::suex::permissions::PermissionsOptionsRegex() {
  static const std::regex re{R"(nopass|persist|keepenv|setenv\s\{.*\})"};
  return re;
}
const std::regex & ::suex::permissions::PermissionLineRegex() {
  static const std::regex re{
      R"(^(permit|deny)\s+((.*)\s+)?((:)?[a-z_][a-z0-9_-]*[$]?)\s+as\s+([a-z_][a-z0-9_-]*[$]?)\s+cmd\s+([^\s]+)(\s+args\s+(([^\s].*[^\s])[\s]*))?\s*$)"};
  return re;
}
const std::regex & ::suex::permissions::CommentLineRegex() {
  static const std::regex re{R"(^[\t|\s]*#.*)"};
  return re;
}
const std::regex & ::suex::permissions::EmptyLineRegex() {
  static const std::regex re{R"(^[\t|\s]*)"};
  return re;
}
const std::regex & ::suex::permissions::QuoteLineRegex() {
  // match ' or " but not \' and \"
  // if that looks weird, a full explanation in the cpp file
  static const std::regex re{R"(('|")(?!\\))"};
  return re;
}
