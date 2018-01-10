#include <auth.h>
#include <conf.h>
#include <glob.h>
#include <logger.h>

#include <security/pam_misc.h>
#include <sstream>

struct auth_data {
  pam_response *pam_resp;
  bool prompt;
};

std::string GetTokenPrefix(const std::string &style) {
  std::string text{style + "__" + RunningUser().Name()};
  return std::to_string(std::hash<std::string>{}(text));
}

std::string GetTokenName(const std::string &style,
                         const std::string &cache_token) {
  std::string prefix{GetTokenPrefix(style)};
  std::string suffix{std::to_string(std::hash<std::string>{}(cache_token))};
  return prefix + suffix;
}

std::string GetFilePath(const std::string &style,
                        const std::string &cache_token) {
  std::stringstream ss;
  ss << PATH_SUEX_TMP << "/" << GetTokenName(style, cache_token) << getsid(0);
  return ss.str();
}

time_t SetToken(time_t ts, const std::string &filename) {
  file::File f{filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IRGRP};
  std::string txt{std::to_string(ts)};
  f.Write(gsl::make_span(txt.c_str(), txt.size()));
  return ts;
}

time_t GetToken(const std::string &filename) {
  file::File f{filename, O_CREAT | O_RDONLY};

  if (!S_ISREG(f.Mode())) {
    throw suex::IOError("auth timestamp is not a file");
  }

  if (!f.IsSecure()) {
    throw suex::PermissionError("auth timestamp file has invalid permissions");
  }

  if (f.Size() > MAX_FILE_SIZE) {
    throw suex::PermissionError("auth timestamp file is too big");
  }

  char buff[f.Size()];
  auto buff_view = gsl::make_span(static_cast<char *>(buff), f.Size());
  ssize_t bytes = f.Read(buff_view);

  time_t ts{0};
  if (bytes > 0) {
    std::istringstream ss(buff_view.data());
    ss >> ts;
  }

  return ts;
}

int PamConversation(int num_msg, const struct pam_message **msg,
                    struct pam_response **resp, void *appdata) {
  logger::debug() << "pam converstaion msg " << num_msg << ": " << (*msg)->msg
                  << std::endl;
  const auto auth_data = static_cast<struct auth_data *>(appdata);
  if (!auth_data->prompt) {
    return PAM_AUTH_ERR;
  }

  std::string prompt{
      Sprintf("[suex] password for %s: ", RunningUser().Name().c_str())};
  auth_data->pam_resp->resp = getpass(prompt.c_str());
  auth_data->pam_resp->resp_retcode = 0;
  *resp = auth_data->pam_resp;
  return PAM_SUCCESS;
}

int auth::ClearTokens(const std::string &style) {
  glob_t globbuf{0};
  std::string glob_pattern{
      Sprintf("%s/%s*", PATH_SUEX_TMP, GetTokenPrefix(style).c_str())};
  if (glob(glob_pattern.c_str(), 0, nullptr, &globbuf) != 0) {
    logger::debug() << "glob returned nothing" << std::endl;
    return 0;
  }

  DEFER(globfree(&globbuf));
  auto paths = gsl::make_span(globbuf.gl_pathv, globbuf.gl_pathc);
  for (std::string token_path : paths) {
    logger::debug() << "clearing: " << token_path << std::endl;
    if (!file::File(token_path, O_RDONLY).Remove(true)) {
      return -1;
    }
  }
  return static_cast<int>(globbuf.gl_pathc);
}

bool auth::StyleExists(const std::string &style) {
  std::string policy_path{Sprintf("%s/%s", PATH_PAM_POlICY, style.c_str())};
  return utils::path::Exists(policy_path);
}

bool auth::Authenticate(const std::string &style, bool prompt,
                        const std::string &cache_token) {
  logger::debug() << "Authenticating | "
                  << "auth style: " << style << " | "
                  << "cache: " << (cache_token.empty() ? "off" : "on") << " | "
                  << "prompt: " << (prompt ? "on" : "off") << std::endl;

  if (!StyleExists(style)) {
    throw suex::AuthError("Invalid PAM policy: policy '%s' doesn't exist",
                          style.c_str());
  }

  std::string ts_filename{GetFilePath(style, cache_token)};

  if (!cache_token.empty()) {
    // check timestamp validity
    time_t ts{GetToken(ts_filename)};
    time_t now{time(nullptr)};

    if (ts < 0 || now < ts) {
      logger::warning() << "invalid auth timestamp: " << ts << std::endl;
      file::File(ts_filename, O_RDONLY).Remove(false);
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

  int retval = pam_start(style.c_str(), RunningUser().Name().c_str(),
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
