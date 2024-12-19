#ifndef PAM_BACKEND_HPP
#define PAM_BACKEND_HPP

#include "pam_globals.hpp"
#include "pam_argument_parser.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/pattern_formatter.h>

#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>

#include <variant>
#include <memory>
#include <regex>

#include <future>
#include <thread>
#include <chrono>
#include <atomic>

#include <pwd.h>

#ifndef UNIX_MAX_RETRIES
    #define UNIX_MAX_RETRIES 3
#endif

#ifndef UNIX_TIMEOUT
    #define UNIX_TIMEOUT 30
#endif

namespace CHOOI
{
class FPrintWrapper
{
public:
    FPrintWrapper();
    FPrintWrapper(const FPrintWrapper&) = delete;
    FPrintWrapper& operator=(const FPrintWrapper&) = delete;

    static std::shared_ptr<FPrintWrapper> getInstance();

public:
    int handlePamRequest(PAM_MODULE_TYPE mode_type, pam_handle_t *pamh, int flags, int argc, const char **argv);

    PAM_RETURN_TYPE handlePamAuthenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
    PAM_RETURN_TYPE handlePamSetCredentials(pam_handle_t *pamh, int flags, int argc, const char **argv);
    PAM_RETURN_TYPE handlePamAccountManagment(pam_handle_t *pamh, int flags, int argc, const char **argv);
    PAM_RETURN_TYPE handlePamOpenSession(pam_handle_t *pamh, int flags, int argc, const char **argv);
    PAM_RETURN_TYPE handlePamCloseSession(pam_handle_t *pamh, int flags, int argc, const char **argv);
    PAM_RETURN_TYPE handlePamChangeAuthenticationToken(pam_handle_t *pamh, int flags, int argc, const char **argv);

public:
    static void cleanupFailures(pam_handle_t* pamh, void* fl, int err);
    static DBusGProxy *createManager(pam_handle_t *pamh, DBusGConnection **ret_conn, GMainLoop **ret_loop);
    static DBusGProxy *openDevice(pam_handle_t *pamh, DBusGConnection *connection, DBusGProxy *manager, const std::string &name);
    static void closeAndUnref(DBusGConnection *connection);
    static PAM_RETURN_TYPE doFignerVerify(GMainLoop *loop, pam_handle_t *pamh, DBusGProxy *dev, std::atomic<bool>& stop_flag);
    static void releaseDevice(pam_handle_t *pamh, DBusGProxy *dev);
    static void verifyResult(GObject *object, const char *result, gboolean done, gpointer user_data);
    static void verifyFingerSelected(GObject *object, const char *finger_name, gpointer user_data);
    static gboolean verifyTimeoutCb(gpointer user_data);

    static gboolean sendMsg(pam_handle_t *pamh, int msg_style, const char *msg);
    static gboolean sendInfoMsg(pam_handle_t *pamh, const char *msg);
    static gboolean sendErrMsg(pam_handle_t *pamh, const char *msg);

    static const char *fingerStrToMsg(const char *finger_name, gboolean is_swipe);
    static const char *verifyResultStrToMsg(const char *result, gboolean is_swipe);

private:
    struct AccountInfo
    {
        passwd password_info;
        spwd shadow_info;
    };

    struct FailedAuth
    {
        int count;
        uid_t uid;
        uid_t euid;
        char* name;
        char* user;
    };

    typedef struct
    {
        guint max_tries;
        char *result;
        gboolean timed_out;
        gboolean is_swipe;
        pam_handle_t *pamh;
        GMainLoop *loop;
        char *driver;
    } VerifyData;
private:
    void handlePamDebug(pam_handle_t *pamh, int flags, int argc, const char **argv);

    std::variant<PAM_RETURN_TYPE, std::string> getPamUsername(pam_handle_t *pamh, const std::string &login_prompt);
    std::variant<PAM_RETURN_TYPE, std::string> getPamPasswordHash(const std::string &name);
    std::variant<PAM_RETURN_TYPE, AccountInfo> getPamAccountInfo(const std::string &name);

    bool isPasswordBlank(ArgumentParser& parser, const std::string& name);

    PAM_RETURN_TYPE authReturn(pam_handle_t* pamh, ArgumentParser& parser, std::unique_ptr<PAM_RETURN_TYPE>& ret_data, PAM_RETURN_TYPE retval);

    PAM_RETURN_TYPE verifyFingerprint(pam_handle_t *pamh, const std::string &name, std::atomic<bool>& stop_flag);
    PAM_RETURN_TYPE verifyPassword(pam_handle_t *pamh, const std::string &name, ArgumentParser& parser, std::atomic<bool>& stop_flag);
    PAM_RETURN_TYPE verifyPasswordHash(pam_handle_t *pamh, const std::string& password, std::string& hash, bool nullok);

    static void secureDelete(const char*& str);
    static void secureDelete(char*& str);
    static void secureDelete(std::string& str);

    void stripHash(std::string &hash);
    std::string_view stripHashPrefix(const std::string& str, std::string_view prefix);

private:
    std::shared_ptr<spdlog::sinks::syslog_sink<std::mutex>> syslog_sink;
    std::shared_ptr<spdlog::logger>                         syslog_logger;
};
}

#endif // PAM_BACKEND_HPP
