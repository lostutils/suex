#include <auth.h>
#include <exceptions.h>
#include <glob.h>
#include <logger.h>
#include <optarg.h>
#include <security/pam_misc.h>
#include <conf.h>
#include <file.h>

using namespace suex;
using namespace suex::optargs;
using namespace suex::utils;
struct auth_data {
  pam_response *pam_resp;
  bool prompt;
};

std::string GetTokenPrefix(const std::string &style) {
  std::string text{style + "__" + running_user.Name()};
  return std::to_string(std::hash<std::string>{}(text));
}

std::string GetTokenName(const std::string &style,
                         const std::string &cache_token) {
  std::string prefix{GetTokenPrefix(style)};
  std::string suffix{std::to_string(std::hash<std::string>{}(cache_token))};
  return prefix + suffix;
}

std::string GetFilepath(const std::string &style,
                        const std::string &cache_token) {
  std::stringstream ss;
  ss << PATH_SUEX_TMP << "/" << GetTokenName(style, cache_token)
     << getsid(0);
  return ss.str();
}

void SetToken(time_t ts, const std::string &filename) {
  FILE *f = fopen(filename.c_str(), "w");
  if (f == nullptr) {
    throw suex::IOError("couldn't open token file for writing");
  }

  DEFER(fclose(f));
  file::Secure(fileno(f));

  file::Buffer buff(fileno(f), std::ios::out);
  std::ostream os(&buff);
  os << ts;
}

time_t GetToken(const std::string &filename) {
  FILE *f = fopen(filename.c_str(), "r");
  DEFER(if (f != nullptr) fclose(f));

  struct stat st{};
  if (fstat(fileno(f), &st) != 0) {
    SetToken(0, filename);

    f = fopen(filename.c_str(), "r");
    if (f == nullptr || fstat(fileno(f), &st) != 0) {
      throw suex::IOError("couldn't open token file for reading");
    }
  }

  if (!S_ISREG(st.st_mode)) {
    throw suex::IOError("auth timestamp is not a file");
  }

  if (!file::IsSecure(fileno(f))) {
    throw suex::PermissionError("auth timestamp file has invalid permissions");
  }

  file::Buffer buff(fileno(f), std::ios::in);
  std::istream is(&buff);
  time_t ts;
  is >> ts;
  return ts;
}

int PamConversation(int, const struct pam_message **,
                    struct pam_response **resp, void *appdata) {
  auto auth_data = *(struct auth_data *) appdata;
  if (!auth_data.prompt) {
    return PAM_AUTH_ERR;
  }

  std::string prompt{utils::StringFormat("[suex] password for %s: ",
                                         running_user.Name().c_str())};
  auth_data.pam_resp->resp = getpass(prompt.c_str());
  auth_data.pam_resp->resp_retcode = 0;
  *resp = auth_data.pam_resp;
  return PAM_SUCCESS;
}

int auth::ClearTokens(const std::string &style) {
  glob_t globbuf{};
  std::string glob_pattern{StringFormat("%s/%s*", PATH_SUEX_TMP,
                                        GetTokenPrefix(style).c_str())};
  int retval = glob(glob_pattern.c_str(), 0, nullptr, &globbuf);
  if (retval != 0) {
    logger::debug() << "glob(\"" << glob_pattern << "\") returned " << retval
                    << std::endl;
    return 0;
  }

  DEFER(globfree(&globbuf));
  for (size_t i = 0; i < globbuf.gl_pathc; i++) {
    std::string token_path{globbuf.gl_pathv[i]};
    logger::debug() << "clearing: " << token_path << std::endl;
    retval = remove(token_path.c_str());
    if (retval != 0) {
      logger::debug() << "remove(\"" << token_path << "\") returned " << retval
                      << std::endl;
      return -1;
    }
  }

  return static_cast<int>(globbuf.gl_pathc);
}

bool auth::StyleExists(const std::string &style) {
  std::string policy_path{
      StringFormat("%s/%s", PATH_PAM_POlICY, style.c_str())};
  return path::Exists(policy_path);
}

bool auth::Authenticate(const std::string &style, bool prompt,
                        const std::string &cache_token) {
  logger::debug() << "Authenticating | "
                  << "auth style: " << style << " | "
                  << "cache: "
                  << (cache_token.empty() ? "off" : "on") << " | "
                  << "prompt: "
                  << (prompt ? "on" : "off") << std::endl;

  if (!StyleExists(style)) {
    throw suex::AuthError("Invalid PAM policy: policy '%s' doesn't exist",
                          style.c_str());
  }

  std::string ts_filename{GetFilepath(style, cache_token)};

  if (!cache_token.empty()) {
    // check timestamp validity
    time_t ts{GetToken(ts_filename)};
    time_t now{time(nullptr)};

    if (ts < 0 || now <= ts) {
      logger::warning() << "invalid auth timestamp: " << ts << std::endl;
      remove(ts_filename.c_str());
      return false;
    }

    // user successfully authenticated less than 5 minutes ago
    if (now - ts < 60 * 5) {
      return true;
    }
  }

  auth_data data{.pam_resp = new (struct pam_response), .prompt = prompt};

  const struct pam_conv pam_conversation = {PamConversation, &data};
  pam_handle_t *handle = nullptr;  // this gets set by pam_start

  int retval = pam_start(style.c_str(), running_user.Name().c_str(),
                         &pam_conversation, &handle);

  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_start returned: " << retval << std::endl;
    return false;
  }

  DEFER({
          retval = pam_end(handle, retval);
          if (retval != PAM_SUCCESS) {
            logger::debug() << "[pam]: pam_end returned " << retval << std::endl;
          }
        });

  retval = pam_authenticate(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_authenticate returned " << retval
                    << std::endl;
    return false;
  }

  retval = pam_acct_mgmt(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_acct_mgmt returned " << retval << std::endl;
    return false;
  }

  retval = pam_close_session(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_close_session returned " << retval
                    << std::endl;
    return false;
  }
  // set the timestamp file
  if (!cache_token.empty()) {
    SetToken(time(nullptr), ts_filename);
  }
  return true;
}
