
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <options.h>
#include <logger.h>
#include <security/pam_appl.h>
#include <sstream>

struct pam_response *auth_reply;
std::string prefix() {
  std::stringstream ss;
  ss << "[doas] password for " << running_user.Name() << ": ";
  return ss.str();
}

int GetPassword(int, const struct pam_message **, struct pam_response **resp, void *) {
  auth_reply = (struct pam_response *) malloc(sizeof(struct pam_response));
  auth_reply->resp = getpass(prefix().c_str());
  auth_reply->resp_retcode = 0;

  *resp = auth_reply;
  return PAM_SUCCESS;
};


bool Authenticate() {
  const struct pam_conv local_conversation = {GetPassword, nullptr};
  pam_handle_t *local_auth_handle = nullptr; // this gets set by pam_start

  int retval = pam_start("su", running_user.Name().c_str(), &local_conversation, &local_auth_handle);

  if (retval != PAM_SUCCESS) {
    logger::debug << "pam_start returned: " << retval << std::endl;
    return false;
  }

  retval = pam_authenticate(local_auth_handle, 0);

  if (retval != PAM_SUCCESS) {
    if (retval == PAM_AUTH_ERR) {
      logger::debug << "Authentication failure" << std::endl;
    } else {
      logger::debug << "pam_authenticate returned " << retval << std::endl;
    }
    return false;
  }

  return pam_end(local_auth_handle, retval) == PAM_SUCCESS;
}

