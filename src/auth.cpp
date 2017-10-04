#include <auth.h>
#include <cstring>
#include <security/pam_misc.h>
#include <options.h>
#include <logger.h>
#include <sstream>
#include <ctime>

std::string GetFilepath(const std::string& service_name) {
  std::stringstream ss;
  std::string filename {service_name + "__" + running_user.Name() + "__" + std::to_string(getsid(0))};
  ss << AUTH_CACHE_DIR << "/" << std::hash<std::string>{}(filename);
  return ss.str();
}

void SetTimestamp(time_t ts, const std::string &filename) {
  std::ofstream f(filename);
  f << ts;
  f.close();

  // chmod 440
  if (chmod(filename.c_str(), S_IRUSR | S_IRGRP) < 0) {
    throw std::runtime_error(std::strerror(errno));
  }
  // chown root:root
  if (chown(filename.c_str(), 0, 0) < 0) {
    throw std::runtime_error(std::strerror(errno));
  }
}

time_t GetTimestamp(const std::string &filename) {
  struct stat path_stat{};

  // create the directory
  if (stat(AUTH_CACHE_DIR, &path_stat) != 0) {
    if (mkdir(AUTH_CACHE_DIR, S_IRUSR | S_IRGRP) < 0) {
      throw std::runtime_error(std::strerror(errno));
    }
    if (chown(AUTH_CACHE_DIR, 0, 0) < 0) {
      throw std::runtime_error(std::strerror(errno));
    }
    if (stat(AUTH_CACHE_DIR, &path_stat) != 0) {
      throw std::runtime_error(std::strerror(errno));
    }
  }

  if (!S_ISDIR(path_stat.st_mode)) {
    throw std::runtime_error("auth timestamp directory is not a directory");
  }

  if (stat(filename.c_str(), &path_stat) != 0) {
    SetTimestamp(0, filename);
    if (stat(filename.c_str(), &path_stat) != 0) {
      throw std::runtime_error(std::strerror(errno));
    }
  }

  if (!S_ISREG(path_stat.st_mode) ||
    path_stat.st_uid != 0 || path_stat.st_gid != 0) {
    throw std::runtime_error("auth timestamp is not a file");
  }

  // config file can only have read permissions for user and group
  if (PermissionBits(path_stat) != 440) {
    throw std::runtime_error("invalid permission bits for auth timestamp file");
  }

  std::ifstream f(filename);
  time_t ts;
  f >> ts;
  f.close();

  return ts;
}

bool Authenticate(const std::string &service_name, bool cache) {
  std::string ts_filename {GetFilepath(service_name)};

  if (cache) {
    // check timestamp validity
    time_t ts { GetTimestamp(ts_filename)};
    if (ts < 0 || (time(nullptr)) - ts < 0) {
      logger::warning << "invalid auth timestamp: " << ts << std::endl;
      remove(ts_filename.c_str());
      return false;
    }

    // user successfully authenticated less than 15 minutes ago
    // extend the token to 15 more minutes and return true.
    if (time(nullptr) - ts > 60 * 15) {
      SetTimestamp(time(nullptr), ts_filename);
      return true;
    }
  }

  const struct pam_conv pam_conversation = {misc_conv, nullptr};
  pam_handle_t *handle = nullptr; // this gets set by pam_start

  int retval = pam_start(service_name.c_str(),
                         running_user.Name().c_str(),
                         &pam_conversation,
                         &handle);

  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_start returned: " << retval << std::endl;
    return false;
  }

  retval = pam_authenticate(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_authenticate returned " << retval << std::endl;
    return false;
  }

  retval = pam_acct_mgmt(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_acct_mgmt returned " << retval << std::endl;
    return false;
  }

  retval = pam_close_session(handle, 0);
  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_close_session returned " << retval << std::endl;
    return false;
  }
  retval = pam_end(handle, retval);
  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_end returned " << retval << std::endl;
    return false;
  }

  // set the timestamp file
  if (cache) {
    SetTimestamp(time(nullptr), ts_filename);
  }
  return true;
}
