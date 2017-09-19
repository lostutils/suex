#include <auth.h>
#include <cstring>
#include <logger.h>
#include <glob.h>
#include <optarg.h>
#include <exceptions.h>
#include <security/pam_misc.h>

using namespace doas;
using namespace doas::optargs;
using namespace doas::utils;
struct auth_data {
  pam_response *pam_resp;
  bool prompt;
};

std::string GetTokenName(const std::string &service_name) {
  std::string token{service_name + "__" + running_user.Name()};
  return std::to_string(std::hash<std::string>{}(token));
}

std::string GetFilepath(const std::string &service_name) {
  std::stringstream ss;
  ss << PATH_DOAS_TMP << "/" << GetTokenName(service_name) << getsid(0);
  return ss.str();
}

void SetToken(time_t ts, const std::string &filename) {
  std::ofstream f(filename);
  DEFER(f.close());
  f << ts;

  // chmod 440
  if (chmod(filename.c_str(), S_IRUSR | S_IRGRP) < 0) {
    throw doas::PermissionError(std::strerror(errno));
  }
  // chown root:root
  if (chown(filename.c_str(), 0, 0) < 0) {
    throw doas::PermissionError(std::strerror(errno));
  }
}

time_t GetToken(const std::string &filename) {
  struct stat fstat{};

  if (stat(filename.c_str(), &fstat) != 0) {
    SetToken(0, filename);
    if (stat(filename.c_str(), &fstat) != 0) {
      throw doas::IOError(std::strerror(errno));
    }
  }

  if (!S_ISREG(fstat.st_mode)) {
    throw doas::IOError("auth timestamp is not a file");
  }

  if (fstat.st_uid != 0 || fstat.st_gid != 0
      || utils::PermissionBits(fstat) != 440) {
    throw doas::PermissionError("auth timestamp file has invalid permissions");
  }

  std::ifstream f(filename);
  DEFER(f.close());
  time_t ts;
  f >> ts;
  return ts;
}

int PamConversation(int, const struct pam_message **, struct pam_response **resp, void *appdata) {
  auto auth_data = *(struct auth_data *) appdata;
  if (!auth_data.prompt) {
    return PAM_AUTH_ERR;
  }

  std::string prompt{utils::StringFormat("[doas] password for %s: ", running_user.Name().c_str())};
  auth_data.pam_resp->resp = getpass(prompt.c_str());
  auth_data.pam_resp->resp_retcode = 0;
  *resp = auth_data.pam_resp;
  return PAM_SUCCESS;
}

int auth::ClearTokens(const std::string &service_name) {

  glob_t globbuf{};
  std::string glob_pattern{StringFormat("%s/%s*",
                                        PATH_DOAS_TMP,
                                        GetTokenName(service_name).c_str())};
  int retval = glob(glob_pattern.c_str(), 0, nullptr, &globbuf);
  if (retval != 0) {
    logger::debug() << "glob(\"" << glob_pattern << "\") returned " << retval << std::endl;
    return 0;
  }

  DEFER(globfree(&globbuf));
  for (size_t i = 0; i < globbuf.gl_pathc; i++) {
    std::string token_path{globbuf.gl_pathv[i]};
    logger::debug() << "clearing: " << token_path << std::endl;
    retval = remove(token_path.c_str());
    if (retval != 0) {
      logger::debug() << "remove(\"" << token_path << "\") returned " << retval << std::endl;
      return -1;
    }
  }

  return static_cast<int>(globbuf.gl_pathc);
}

bool auth::PolicyExists(const std::string &service_name) {
  std::string policy_path{StringFormat("%s/%s", PATH_PAM_POlICY,
                                       service_name.c_str())};
  return path::Exists(policy_path);
}

bool auth::Authenticate(const std::string &service_name, bool cache, bool prompt) {
  logger::debug() << "Authenticating | " <<
                  "policy: " << service_name << " | "
                      "cache: " << (cache ? "on" : "off") << " | "
                      "prompt: " << (prompt ? "on" : "off")
                  << std::endl;

  if (!PolicyExists(service_name)) {
    throw doas::AuthError("Invalid PAM policy: policy '%s' doesn't exist",
                          service_name.c_str());
  }

  std::string ts_filename{GetFilepath(service_name)};

  if (cache) {
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

  auth_data data{
      .pam_resp = new (struct pam_response),
      .prompt = prompt
  };

  const struct pam_conv pam_conversation = {PamConversation, &data};
  pam_handle_t *handle = nullptr; // this gets set by pam_start

  int retval = pam_start(service_name.c_str(),
                         running_user.Name().c_str(),
                         &pam_conversation,
                         &handle);

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
    logger::debug() << "[pam]: pam_authenticate returned " << retval << std::endl;
    return false;
  }

  retval = pam_acct_mgmt(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_acct_mgmt returned " << retval << std::endl;
    return false;
  }

  retval = pam_close_session(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug() << "[pam]: pam_close_session returned " << retval << std::endl;
    return false;
  }
  // set the timestamp file
  if (cache) {
    SetToken(time(nullptr), ts_filename);
  }
  return true;
}
