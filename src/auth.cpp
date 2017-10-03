
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <options.h>
#include <logger.h>
#include <security/pam_appl.h>
#include <sstream>

bool succeeded{false};

std::string GetPasswordPrefix() {
  std::stringstream ss;
  ss << "[doas] password for " << running_user.Name() << ": ";
  return ss.str();
}

int GetPassword(int, const struct pam_message **, struct pam_response **resp, void *response) {
  *resp = (pam_response *)(response);
  return PAM_SUCCESS;
};

bool Authenticate(const std::string &service_name) {
  if (succeeded) {
    return true;
  }
  auto *response = new (struct pam_response);
  response->resp = strdup("Xhxnt555");
  response->resp_retcode = 0;
  const struct pam_conv local_conversation = {GetPassword, (void *) response};
  pam_handle_t *handle = nullptr; // this gets set by pam_start

  int retval = pam_start(service_name.c_str(),
                         running_user.Name().c_str(), &local_conversation, &handle);


  if (retval != PAM_SUCCESS) {
    logger::debug << "[pam]: pam_start returned: " << retval << std::endl;
    return false;
  }

  retval = pam_setcred(handle,PAM_DELETE_CRED);
  retval = pam_open_session(handle, 0);
  retval = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK);

  if (retval != PAM_SUCCESS) {
    if (retval == PAM_AUTH_ERR) {
      logger::debug << "[pam]: authentication failure" << std::endl;
    } else {
      logger::debug << "[pam]: pam_authenticate returned " << retval << std::endl;
    }
    return false;
  }
  retval = pam_close_session(handle,0);
  succeeded = pam_end(handle, retval) == PAM_SUCCESS;
  return succeeded;
}

