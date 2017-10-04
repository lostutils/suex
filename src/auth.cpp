#include <auth.h>
#include <cstring>
#include <security/pam_misc.h>
#include <options.h>
#include <logger.h>
#include <sstream>
#include <ctime>

std::string GetFilename() {
  std::stringstream ss;
  ss << AUTH_CACHE_DIR << "/" << getsid(0) << "_" << std::hash<std::string>{}(running_user.Name());
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
    throw std::runtime_error("not a directory");
  }

  if (stat(filename.c_str(), &path_stat) != 0) {
    SetTimestamp(0, filename);
    if (stat(filename.c_str(), &path_stat) != 0) {
      throw std::runtime_error(std::strerror(errno));
    }
  }

  if (!S_ISREG(path_stat.st_mode) ||
    path_stat.st_uid != 0 || path_stat.st_gid != 0) {
    throw std::runtime_error("wtf not a file");
  }

  // config file can only have read permissions for user and group
  int permbits { PermissionBits(path_stat)};
  if (permbits != 440) {
    std::stringstream ss;
    ss << "invalid permission bits: " << permbits;
    throw std::runtime_error(ss.str());
  }

  std::ifstream f(filename);
  time_t ts;
  f >> ts;
  return ts;
}

bool Authenticate(const std::string &service_name, bool cache) {
  std::string ts_filename { GetFilename()};
  if (cache) {
    time_t elapsed_secs = time(nullptr) - GetTimestamp(ts_filename);
    if (elapsed_secs < 60 * 15) {
      return true;
    }
    remove(ts_filename.c_str());
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

  if (cache) {
    SetTimestamp(time(nullptr), ts_filename);
  }
  return true;
}
