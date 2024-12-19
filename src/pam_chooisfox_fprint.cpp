#include "pam_backend.hpp"

PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::AUTHENTICATE, pamh, flags, argc, argv);
}

/* NOT IMPLEMENTED YET*/
PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::SETCRED, pamh, flags, argc, argv);
}

PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::ACCT_MGMT, pamh, flags, argc, argv);
}

PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::OPEN_SESSION, pamh, flags, argc, argv);
}

PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::CLOSE_SESSION, pamh, flags, argc, argv);
}

PAM_EXTERN int __attribute__((visibility("default"))) pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return CHOOI::FPrintWrapper::getInstance()->handlePamRequest(CHOOI::PAM_MODULE_TYPE::CHAUTHTOK, pamh, flags, argc, argv);
}
/**/
