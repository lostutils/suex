#include <auth.h>
#include <exceptions.h>
#include <glob.h>
#include <logger.h>
#include <optarg.h>
#include <security/pam_misc.h>
#include <conf.h>
#include <file.h>
#include <ext/stdio_filebuf.h>

using namespace suex;
using namespace suex::optargs;
using namespace suex::utils;
struct auth_data {
  pam_response *pam_resp;
  bool prompt;
};

std::string GetTokenPrefix(const std::string &service_name) {
  std::string text{service_name + "__" + running_user.Name()};
  return std::to_string(std::hash<std::string>{}(text));
}

std::string GetTokenName(const std::string &service_name,
                         const std::string &cache_token) {
  std::string prefix{GetTokenPrefix(service_name)};
  std::string suffix{std::to_string(std::hash<std::string>{}(cache_token))};
  return prefix + suffix;
}

std::string GetFilepath(const std::string &service_name,
                        const std::string &cache_token) {
  std::stringstream ss;
  ss << PATH_SUEX_TMP << "/" << GetTokenName(service_name, cache_token)
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
  struct stat fstat{};

  if (stat(filename.c_str(), &fstat) != 0) {
    SetToken(0, filename);
    if (stat(filename.c_str(), &fstat) != 0) {
      throw suex::IOError(std::strerror(errno));
    }
  }

  if (!S_ISREG(fstat.st_mode)) {
    throw suex::IOError("auth timestamp is not a file");
  }

  if (!file::IsSecure(filename)) {
    throw suex::PermissionError("auth timestamp file has invalid permissions");
  }

  std::ifstream f(filename);
  DEFER(f.close());
  time_t ts;
  f >> ts;
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

int auth::ClearTokens(const std::string &service_name) {
  glob_t globbuf{};
  std::string glob_pattern{StringFormat("%s/%s*", PATH_SUEX_TMP,
                                        GetTokenPrefix(service_name).c_str())};
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

bool auth::PolicyExists(const std::string &service_name) {
  std::string policy_path{
      StringFormat("%s/%s", PATH_PAM_POlICY, service_name.c_str())};
  return path::Exists(policy_path);
}

bool auth::Authenticate(const std::string &service_name, bool prompt,
                        const std::string &cache_token) {
  logger::debug() << "Authenticating | "
                  << "policy: " << service_name << " | "
                  << "cache: "
                  << (cache_token.empty() ? "off" : "on") << " | "
                  << "prompt: "
                  << (prompt ? "on" : "off") << std::endl;

  if (!PolicyExists(service_name)) {
    throw suex::AuthError("Invalid PAM policy: policy '%s' doesn't exist",
                          service_name.c_str());
  }

  std::string ts_filename{GetFilepath(service_name, cache_token)};

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

  int retval = pam_start(service_name.c_str(), running_user.Name().c_str(),
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
