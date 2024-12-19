#include "pam_backend.hpp"
#include "pam_hasher.hpp"

#include <security/_pam_types.h>
#include <spdlog/spdlog.h>

namespace
{
constexpr auto PAM_FAIL_PREFIX = "-UN*X-PASS";

constexpr auto PAM_AUTH_COMMENT = "Please enter password or place finger:";
constexpr auto PAM_AUTH_PROMPT = "Password: ";

constexpr auto PAM_USER_REGEX = "^[a-z_][a-z0-9_]{0,256}$";

constexpr std::string_view VALID_HASH_SYMBOLS =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789./";
}

namespace CHOOI
{
FPrintWrapper::FPrintWrapper()
{
    syslog_sink   = std::make_shared<spdlog::sinks::syslog_sink_mt>("pam_chooisfox", LOG_PID, LOG_USER, true);
    syslog_logger = std::make_shared<spdlog::logger>("syslog_logger", syslog_sink);

	spdlog::set_default_logger(syslog_logger);
}

std::shared_ptr<FPrintWrapper> FPrintWrapper::getInstance()
{
    static std::shared_ptr<FPrintWrapper> instance(new FPrintWrapper);

    return instance;
}

int FPrintWrapper::handlePamRequest(PAM_MODULE_TYPE mode_type, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    PAM_RETURN_TYPE result;

	switch (mode_type)
	{
        case PAM_MODULE_TYPE::AUTHENTICATE:
        {
            result = handlePamAuthenticate(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::SETCRED:
        {
            result = handlePamSetCredentials(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::ACCT_MGMT:
        {
            result = handlePamAccountManagment(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::OPEN_SESSION:
        {
            result = handlePamOpenSession(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::CLOSE_SESSION:
        {
            result = handlePamCloseSession(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::CHAUTHTOK:
        {
            result = handlePamChangeAuthenticationToken(pamh, flags, argc, argv);
        }
        break;

        case PAM_MODULE_TYPE::INVALID:
        default:
        {
            result = PAM_RETURN_TYPE::MODULE_UNKNOWN;
        }
        break;
	}

    return static_cast<int>(result);
}

PAM_RETURN_TYPE FPrintWrapper::handlePamAuthenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Authenticate requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

    std::unique_ptr<PAM_RETURN_TYPE> return_data;

    ArgumentParser parser;
    parser.genControlSequence(flags, NULL, NULL, NULL, argc, argv);

    if (parser.hasFlag(PAM_ARGUMENT::UNIX_LIKE_AUTH))
    {
        return_data = std::make_unique<PAM_RETURN_TYPE>();
    }

    std::string username;

    auto username_result = getPamUsername(pamh, PAM_AUTH_PROMPT);

    if (std::holds_alternative<PAM_RETURN_TYPE>(username_result))
    {
        return authReturn(pamh, parser, return_data, std::get<PAM_RETURN_TYPE>(username_result));
    }
    else
    {
        username = std::get<std::string>(username_result);
    }

    if (!std::regex_match(username, std::regex(PAM_USER_REGEX)))
    {
        spdlog::error("Invalid username: {}", username);
        return authReturn(pamh, parser, return_data, PAM_RETURN_TYPE::USER_UNKNOWN);
    }

    if (parser.hasFlag(PAM_ARGUMENT::DEBUG))
    {
        spdlog::info("Username: {}", username);
    }

    if (isPasswordBlank(parser, username))
    {
        spdlog::info("Username: {} has no password", username);
        username = "";

        return authReturn(pamh, parser, return_data, PAM_RETURN_TYPE::SUCCESS);
    }

    std::atomic<bool> stop_other_auth(false);

    std::future<PAM_RETURN_TYPE> password_future = std::async(std::launch::async, [&]()
    {
        return verifyPassword(pamh, username, parser, stop_other_auth);
    });

    std::future<PAM_RETURN_TYPE> fingerprint_future = std::async(std::launch::async, [&]() {
        return verifyFingerprint(pamh, username, stop_other_auth);
    });

    while (password_future.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready &&
           fingerprint_future.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready)
    {
        // Do stuff
    }

    PAM_RETURN_TYPE return_value;

    if (password_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready)
    {
        return_value = password_future.get();

        stop_other_auth = true;
    }
    else
    {
        return_value = fingerprint_future.get();

        stop_other_auth = true;
    }


	return authReturn(pamh, parser, return_data, return_value);
}

PAM_RETURN_TYPE FPrintWrapper::authReturn(pam_handle_t* pamh, ArgumentParser& parser, std::unique_ptr<PAM_RETURN_TYPE>& ret_data, PAM_RETURN_TYPE retval)
{
    if (parser.hasFlag(PAM_ARGUMENT::UNIX_LIKE_AUTH) && ret_data)
    {
        *ret_data = retval;

        auto deleter = [](pam_handle_t* pamh, void* data, int error_status)
        {
            UNUSED(pamh);
            UNUSED(error_status);
            delete static_cast<PAM_RETURN_TYPE*>(data);
        };

        if (pam_set_data(pamh, "unix_setcred_return", ret_data.get(), deleter) != static_cast<int>(PAM_RETURN_TYPE::SUCCESS))
        {
            deleter(pamh, ret_data.release(), 0);
            spdlog::error("Error setting data with pam_set_data");
        }
    }

    spdlog::debug("Auth done: {}", pam_strerror(pamh, static_cast<int>(retval)));
    return retval;
}

bool FPrintWrapper::isPasswordBlank(ArgumentParser& parser, const std::string& name)
{
    if (parser.hasFlag(PAM_ARGUMENT::NO_NULL))
    {
        return false;
    }

    auto username_result = getPamPasswordHash(name);

    if (std::holds_alternative<PAM_RETURN_TYPE>(username_result))
    {
        spdlog::error("Error getting password hash");
        return false;
    }

    return std::get<std::string>(username_result).empty();
}

PAM_RETURN_TYPE FPrintWrapper::handlePamSetCredentials(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Set Credentials requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

	return PAM_RETURN_TYPE::SUCCESS;
}

PAM_RETURN_TYPE FPrintWrapper::handlePamAccountManagment(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Account Managment requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

	return PAM_RETURN_TYPE::SUCCESS;
}

PAM_RETURN_TYPE FPrintWrapper::handlePamOpenSession(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Open Session requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

	return PAM_RETURN_TYPE::SUCCESS;
}

PAM_RETURN_TYPE FPrintWrapper::handlePamCloseSession(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Close Session requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

	return PAM_RETURN_TYPE::SUCCESS;
}

PAM_RETURN_TYPE FPrintWrapper::handlePamChangeAuthenticationToken(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	spdlog::info("PAM Change Authentification Token requested\n");

#ifndef CMAKE_RELEASE
    handlePamDebug(pamh, flags, argc, argv);
#endif

	return PAM_RETURN_TYPE::SUCCESS;
}

void FPrintWrapper::handlePamDebug(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    spdlog::info("===============================================================");

    spdlog::info("Flags: {:#x}", flags);

    spdlog::info("Handle: {}", pamh ? static_cast<const void*>(pamh) : "NULL" );

    spdlog::info("Number of arguments: {}", argc);
    std::vector<std::string> args_vector;
    for (int i = 0; i < argc; ++i)
    {
        args_vector.push_back(argv[i]);
        spdlog::info("Argument {}: {}", i, argv[i]);
    }

    const char *service_name = nullptr;
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service_name) == PAM_SUCCESS)
    {
        spdlog::info("PAM service name: {}", service_name ? service_name : "NULL");
    }
    else
    {
        spdlog::error("Failed to retrieve PAM service name");
    }

    const char *user_name = nullptr;
    if (pam_get_user(pamh, &user_name, nullptr) == PAM_SUCCESS)
    {
        spdlog::info("PAM user name: {}", user_name ? user_name : "NULL");
    }
    else
    {
        spdlog::info("Failed to retrieve PAM user name (may not be available yet)");
    }

    const char *rhost = nullptr;
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS)
    {
        spdlog::info("PAM remote host: {}", rhost ? rhost : "NULL");
    }
    else
    {
        spdlog::error("Failed to retrieve PAM remote host");
    }

    const char *tty = nullptr;
    if (pam_get_item(pamh, PAM_TTY, (const void **)&tty) == PAM_SUCCESS)
    {
        spdlog::info("PAM tty: {}", tty ? tty : "NULL");
    }
    else
    {
        spdlog::error("Failed to retrieve PAM tty");
    }

    spdlog::info("===============================================================");
}

std::variant<PAM_RETURN_TYPE, std::string> FPrintWrapper::getPamUsername(pam_handle_t *pamh, const std::string &login_prompt)
{
    PAM_RETURN_TYPE retval;

    const char* name;

    retval = static_cast<PAM_RETURN_TYPE>(pam_get_user(pamh, &name, login_prompt.c_str()));

    if (retval != PAM_RETURN_TYPE::SUCCESS)
    {
        spdlog::error("Unable to retrive username");

        if (retval == PAM_RETURN_TYPE::CONV_AGAIN)
        {
            spdlog::error("pam_get_user/conv() ");
            return PAM_RETURN_TYPE::INCOMPLETE;
        }
    }

    return std::string(name);
}

std::variant<PAM_RETURN_TYPE, std::string> FPrintWrapper::getPamPasswordHash(const std::string &name)
{
    auto account_info_result = getPamAccountInfo(name);

    if (std::holds_alternative<PAM_RETURN_TYPE>(account_info_result))
    {
        return std::get<PAM_RETURN_TYPE>(account_info_result);
    }

    auto account_info = std::get<AccountInfo>(account_info_result);

    if (!account_info.shadow_info.sp_namp)
    {
         return std::string(account_info.password_info.pw_passwd);
    }
    else
    {
        return std::string(account_info.shadow_info.sp_pwdp);
    }

}

std::variant<PAM_RETURN_TYPE, FPrintWrapper::AccountInfo> FPrintWrapper::getPamAccountInfo(const std::string &name)
{
    passwd *pwd = getpwnam(name.c_str());
    spwd *spwdent = nullptr;

    if (pwd != nullptr)
    {
        if (strcmp(pwd->pw_passwd, "*NP*") == 0)
        {
            uid_t save_euid, save_uid;

            save_euid = geteuid();
            save_uid = getuid();
            if (save_uid == pwd->pw_uid)
            {
                if (setreuid(save_euid, save_uid))
                {
                    return PAM_RETURN_TYPE::CRED_INSUFFICIENT;
                }
            }
            else
            {
                if (setreuid(0, -1))
                {
                    return PAM_RETURN_TYPE::CRED_INSUFFICIENT;
                }
                if (setreuid(-1, pwd->pw_uid))
                {
                    if (setreuid(-1, 0) || setreuid(0, -1) ||
                        setreuid(-1, pwd->pw_uid))
                    {
                        return PAM_RETURN_TYPE::CRED_INSUFFICIENT;
                    }
                }
            }

            spwdent = getspnam(name.c_str());
            if (save_uid == pwd->pw_uid)
            {
                if (setreuid(save_uid, save_euid))
                {
                    return PAM_RETURN_TYPE::CRED_INSUFFICIENT;
                }
            }
            else
            {
                if (setreuid(-1, 0) || setreuid(save_uid, -1) ||
                    setreuid(-1, save_euid))
                {
                    return PAM_RETURN_TYPE::CRED_INSUFFICIENT;
                }
            }

            if (spwdent == nullptr || spwdent->sp_pwdp == nullptr)
            {
                return PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
            }

        }
        else if (strcmp(pwd->pw_passwd, "x") == 0 ||
                 ((pwd->pw_passwd[0] == '#') &&
                  (pwd->pw_passwd[1] == '#') &&
                  (strcmp(pwd->pw_name, pwd->pw_passwd + 2) == 0))) // Check is password is shadowed
        {
            spwdent = getspnam(name.c_str());
            if (spwdent == nullptr || spwdent->sp_pwdp == nullptr)
            {
                return PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
            }
        }
    }
    else
    {
        return PAM_RETURN_TYPE::USER_UNKNOWN;
    }

    AccountInfo info;
    info.password_info = *pwd;

    if (spwdent != nullptr)
    {
        info.shadow_info = *spwdent;
    }
    else
    {
        info.shadow_info = {};
    }

    return info;
}

PAM_RETURN_TYPE FPrintWrapper::verifyFingerprint(pam_handle_t *pamh, const std::string &name, std::atomic<bool>& stop_flag)
{
    g_type_init();

    DBusGProxy *manager;
    DBusGConnection *connection;
    DBusGProxy *dev;
    GMainLoop *loop;
    PAM_RETURN_TYPE ret;

    manager = createManager(pamh, &connection, &loop);
    if (manager == NULL)
    {
        return PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
    }

    dev = openDevice(pamh, connection, manager, name);
    g_object_unref(manager);
    if (!dev)
    {
        g_main_loop_unref(loop);
        closeAndUnref(connection);
        return PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
    }

    ret = doFignerVerify(loop, pamh, dev, stop_flag);

    g_main_loop_unref(loop);
    releaseDevice(pamh, dev);
    g_object_unref(dev);
    closeAndUnref(connection);

    return ret;
}

void FPrintWrapper::releaseDevice(pam_handle_t *pamh, DBusGProxy *dev)
{
    GError *error = NULL;
    if (!dbus_g_proxy_call(dev, "Release", &error, G_TYPE_INVALID,
                         G_TYPE_INVALID))
    {
        spdlog::error("ReleaseDevice failed: {}", error->message);
        g_error_free(error);
    }
}

PAM_RETURN_TYPE FPrintWrapper::doFignerVerify(GMainLoop *loop, pam_handle_t *pamh, DBusGProxy *dev, std::atomic<bool>& stop_flag)
{
    GError *error = NULL;
    GHashTable *props;
    DBusGProxy *p;
    VerifyData *data;
    PAM_RETURN_TYPE ret;

    data = g_new0(VerifyData, 1);
    data->max_tries = UNIX_MAX_RETRIES;
    data->pamh = pamh;
    data->loop = loop;

    p = dbus_g_proxy_new_from_proxy(dev, "org.freedesktop.DBus.Properties", NULL);
    if (dbus_g_proxy_call(
          p, "GetAll", NULL, G_TYPE_STRING, "net.reactivated.Fprint.Device",
          G_TYPE_INVALID,
          dbus_g_type_get_map("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
          &props, G_TYPE_INVALID))
    {
        const char *scan_type;
        data->driver =
            g_value_dup_string((const GValue *)g_hash_table_lookup(props, "name"));
        scan_type = g_value_dup_string((const GValue *)g_hash_table_lookup(props, "scan-type"));
        if (g_str_equal(scan_type, "swipe"))
        {
            data->is_swipe = TRUE;
        }
        g_hash_table_destroy(props);
    }
    g_object_unref(p);

    if (!data->driver)
    {
        data->driver = g_strdup("Fingerprint reader");
    }

    dbus_g_proxy_add_signal(dev, "VerifyStatus", G_TYPE_STRING, G_TYPE_BOOLEAN, NULL);
    dbus_g_proxy_add_signal(dev, "VerifyFingerSelected", G_TYPE_STRING, NULL);
    dbus_g_proxy_connect_signal(dev, "VerifyStatus", G_CALLBACK(verifyResult), data, NULL);
    dbus_g_proxy_connect_signal(dev, "VerifyFingerSelected",  G_CALLBACK(verifyFingerSelected), data, NULL);

    ret = PAM_RETURN_TYPE::AUTH_ERR;

    while (ret == PAM_RETURN_TYPE::AUTH_ERR && data->max_tries > 0 && !stop_flag)
    {
        GSource *source = nullptr;
        guint timeout_id = 0;
        GError *error = nullptr;

        source = g_timeout_source_new_seconds(UNIX_TIMEOUT);
        timeout_id = g_source_attach(source, g_main_loop_get_context(loop));
        g_source_set_callback(source, verifyTimeoutCb, data, NULL);

        data->timed_out = FALSE;

        if (!dbus_g_proxy_call(dev, "VerifyStart", &error, G_TYPE_STRING, "any", G_TYPE_INVALID, G_TYPE_INVALID))
        {
            spdlog::error("VerifyStart failed 1: {}", error->message);
            g_error_free(error);
            error = nullptr;

            g_source_remove(timeout_id);
            g_source_unref(source);
            source = nullptr;
            timeout_id = 0;
            break;
        }

        g_main_loop_run(loop);

        if (timeout_id > 0) {
            g_source_remove(timeout_id);
        }

        if (source != nullptr) {
            g_source_unref(source);
        }

        dbus_g_proxy_call(dev, "VerifyStop", &error, G_TYPE_INVALID, G_TYPE_INVALID);
        if (error != nullptr) {
            spdlog::error("VerifyStop failed 2: {}", error->message);
            g_error_free(error);
            error = nullptr;
        }

        if (data->timed_out)
        {
            ret = PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
            break;
        }
        else
        {
            if (g_str_equal(data->result, "verify-no-match"))
            {
                sendErrMsg(data->pamh, "Failed to match fingerprint");
                ret = PAM_RETURN_TYPE::AUTH_ERR;
            }
            else if (g_str_equal(data->result, "verify-match"))
            {
                ret = PAM_RETURN_TYPE::SUCCESS;
            }
            else if (g_str_equal(data->result, "verify-unknown-error"))
            {
                ret = PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
            }
            else if (g_str_equal(data->result, "verify-disconnected"))
            {
                ret = PAM_RETURN_TYPE::AUTHINFO_UNAVAIL;
                g_free(data->result);
                break;
            }
            else
            {
                sendInfoMsg(data->pamh, "An unknown error occured");
                ret = PAM_RETURN_TYPE::AUTH_ERR;
                g_free(data->result);
                break;
            }
            g_free(data->result);
            data->result = NULL;
        }
        data->max_tries--;
    }
    dbus_g_proxy_disconnect_signal(dev, "VerifyStatus", G_CALLBACK(verifyResult), data);
    dbus_g_proxy_disconnect_signal(dev, "VerifyFingerSelected", G_CALLBACK(verifyFingerSelected), data);

    g_free(data->driver);
    g_free(data);

    return ret;
}

gboolean FPrintWrapper::sendMsg(pam_handle_t *pamh, int msg_style, const char *msg)
{
    const struct pam_message mymsg =
    {
        .msg_style = msg_style,
        .msg = msg,
    };
    const struct pam_message *msgp = &mymsg;
    const struct pam_conv *pc;
    struct pam_response *resp;
    int r;

    r = pam_get_item(pamh, PAM_CONV, (const void **)&pc);
    if (r != PAM_SUCCESS || !pc || !pc->conv)
    {
        return FALSE;
    }

    return (pc->conv(1, &msgp, &resp, pc->appdata_ptr) == PAM_SUCCESS);
}

gboolean FPrintWrapper::sendInfoMsg(pam_handle_t *pamh, const char *msg)
{
    return sendMsg(pamh, PAM_TEXT_INFO, msg);
}

gboolean FPrintWrapper::sendErrMsg(pam_handle_t *pamh, const char *msg)
{
    return sendMsg(pamh, PAM_ERROR_MSG, msg);
}

gboolean FPrintWrapper::verifyTimeoutCb(gpointer user_data)
{
    VerifyData *data = (VerifyData *)user_data;

    data->timed_out = TRUE;
    sendInfoMsg(data->pamh, "Verification timed out");
    g_main_loop_quit(data->loop);

    return FALSE;
}

void FPrintWrapper::verifyFingerSelected(GObject *object, const char *finger_name, gpointer user_data)
{
    VerifyData *data = (VerifyData *)user_data;
    char *msg;

    if (g_str_equal(finger_name, "any"))
    {
        if (data->is_swipe == FALSE)
        {
            msg = g_strdup_printf("Place your finger on %s", data->driver);
        }
        else
        {
            msg = g_strdup_printf("Swipe your finger on %s", data->driver);
        }
    }
    else
    {
        msg = g_strdup_printf(fingerStrToMsg(finger_name, data->is_swipe),
                          data->driver);
    }
    //D(data->pamh, "verify_finger_selected %s", msg);
    sendInfoMsg(data->pamh, msg);
    g_free(msg);
}


void FPrintWrapper::verifyResult(GObject *object, const char *result, gboolean done, gpointer user_data)
{
    VerifyData *data = (VerifyData *)user_data;
    const char *msg;

    if (done != FALSE)
    {
        data->result = g_strdup(result);
        g_main_loop_quit(data->loop);
        return;
    }

    msg = verifyResultStrToMsg(result, data->is_swipe);
    spdlog::error("{}", msg);
}


DBusGProxy *FPrintWrapper::createManager(pam_handle_t *pamh, DBusGConnection **ret_conn, GMainLoop **ret_loop)
{
    DBusGConnection *connection;
    DBusConnection *conn;
    DBusGProxy *manager;
    DBusError error;
    GMainLoop *loop;
    GMainContext *ctx;

    connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
    if (connection != NULL)
    {
        dbus_g_connection_unref(connection);
    }

    dbus_error_init(&error);
    conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
    if (conn == NULL)
    {
        spdlog::error("Error with getting the bus");
        dbus_error_free(&error);
        return NULL;
    }

    ctx = g_main_context_new();
    loop = g_main_loop_new(ctx, FALSE);
    g_main_context_unref(ctx);
    dbus_connection_setup_with_g_main(conn, ctx);

    connection = dbus_connection_get_g_connection(conn);

    manager = dbus_g_proxy_new_for_name(
                    connection, "net.reactivated.Fprint",
                                "/net/reactivated/Fprint/Manager",
                                "net.reactivated.Fprint.Manager");
    *ret_conn = connection;
    *ret_loop = loop;

    return manager;
}

const char *FPrintWrapper::verifyResultStrToMsg(const char *result, gboolean is_swipe)
{
	if (g_str_equal (result, "verify-no-match") ||
	    g_str_equal (result, "verify-no-enroll-data") ||
	    g_str_equal (result, "verify-unknown-error"))
	{
		return "An unknown error has occurred.";
	}
	else if (g_str_equal (result, "verify-retry-scan"))
	{
		if (is_swipe)
			return "Swipe too short, try swiping again.";
		else
			return "Try placing your finger on the reader again.";
	}
	else if (g_str_equal (result, "verify-retry-finger-not-centered"))
	{
		return "Place your finger centered on the reader.";
	}
	else if (g_str_equal (result, "verify-retry-remove-and-retry"))
	{
		return "Remove your finger and then try again.";
	}
	else if (g_str_equal (result, "verify-retry-too-fast"))
	{
		return "Swipe too fast, try swiping slower.";
	}
	else
	{
		return result;
	}
}

const char *FPrintWrapper::fingerStrToMsg(const char *finger_name, gboolean is_swipe)
{
	std::string msg;

	if (g_str_equal (finger_name, "right-index-finger"))
	{
		msg = (is_swipe) ? "Swipe your right index finger on %s" : "Place your right index finger on %s";
	}
	else if (g_str_equal (finger_name, "right-middle-finger"))
	{
		msg = (is_swipe) ? "Swipe your right middle finger on %s" : "Place your right middle finger on %s";
	}
	else if (g_str_equal (finger_name, "right-ring-finger"))
	{
		msg = (is_swipe) ? "Swipe your right ring finger on %s" : "Place your right ring finger on %s";
	}
	else if (g_str_equal (finger_name, "right-little-finger"))
	{
		msg = (is_swipe) ? "Swipe your right little finger on %s" : "Place your right little finger on %s";
	}
	else if (g_str_equal (finger_name, "right-thumb"))
	{
		msg = (is_swipe) ? "Swipe your right thumb on %s" : "Place your right thumb on %s";
	}
	else if (g_str_equal (finger_name, "left-index-finger"))
	{
		msg = (is_swipe) ? "Swipe your left index finger on %s" : "Place your left index finger on %s";
	}
	else if (g_str_equal (finger_name, "left-middle-finger"))
	{
		msg = (is_swipe) ? "Swipe your left middle finger on %s" : "Place your left middle finger on %s";
	}
	else if (g_str_equal (finger_name, "left-ring-finger"))
	{
		msg = (is_swipe) ? "Swipe your left ring finger on %s" : "Place your left ring finger on %s";
	}
	else if (g_str_equal (finger_name, "left-little-finger"))
	{
		msg = (is_swipe) ? "Swipe your left little finger on %s" : "Place your left little finger on %s";
	}
	else if (g_str_equal (finger_name, "left-thumb"))
	{
		msg = (is_swipe) ? "Swipe your left thumb on %s" : "Place your left thumb on %s";
	}
	else
	{
		msg = (is_swipe) ? "Swipe your finger on %s" : "Place your finger on %s";
	}

	return msg.c_str();
}


DBusGProxy *FPrintWrapper::openDevice(pam_handle_t *pamh, DBusGConnection *connection, DBusGProxy *manager, const std::string &name)
{
    GError *error = NULL;
    gchar *path;
    DBusGProxy *dev;

    if (!dbus_g_proxy_call(manager, "GetDefaultDevice", &error, G_TYPE_INVALID,
                         DBUS_TYPE_G_OBJECT_PATH, &path, G_TYPE_INVALID))
    {
        spdlog::error("get_default_devices failed: {}", error->message);
        g_error_free(error);
        return NULL;
    }

    if (path == NULL)
    {

        spdlog::error("No devices found");
        return NULL;
    }


    dev = dbus_g_proxy_new_for_name(connection, "net.reactivated.Fprint", path,
                                  "net.reactivated.Fprint.Device");
    g_free(path);

    if (!dbus_g_proxy_call(dev, "Claim", &error, G_TYPE_STRING, name.c_str(),
                         G_TYPE_INVALID, G_TYPE_INVALID))
    {
        spdlog::error("failed to claim device: {}", error->message);
        g_error_free(error);
        g_object_unref(dev);
        return NULL;
    }
    return dev;
}

void FPrintWrapper::closeAndUnref(DBusGConnection *connection)
{
    DBusConnection *conn = dbus_g_connection_get_connection(connection);
    dbus_connection_close(conn);
    dbus_g_connection_unref(connection);
}

PAM_RETURN_TYPE FPrintWrapper::verifyPassword(pam_handle_t *pamh, const std::string &name, ArgumentParser& parser, std::atomic<bool>& stop_flag)
{
    PAM_RETURN_TYPE return_value = PAM_RETURN_TYPE::SUCCESS;
    PAM_HANDLE_TYPE authtok_flag;
    std::string data_username = PAM_FAIL_PREFIX;
    data_username += name;

    std::variant<PAM_RETURN_TYPE, std::string> username_result;

    std::string hash;
    const char *password = nullptr;
    char *user_password = nullptr;

    authtok_flag = parser.hasFlag(PAM_ARGUMENT::OLD_PASSWORD) ? PAM_HANDLE_TYPE::OLDAUTHTOK : PAM_HANDLE_TYPE::AUTHTOK;

    if (parser.hasFlag(PAM_ARGUMENT::TRY_FIRST_PASSWORD) || parser.hasFlag(PAM_ARGUMENT::USE_FIRST_PASSWORD))
    {
        return_value = static_cast<PAM_RETURN_TYPE>(pam_get_item(pamh, static_cast<int>(authtok_flag), (const void **)&password));
        if (return_value != PAM_RETURN_TYPE::SUCCESS)
        {
            spdlog::error("Failed to retrieve entered password");
        }
        else if (password != nullptr)
        {
            spdlog::info("Skip login");

            if (parser.noFlag(PAM_ARGUMENT::NO_NULL))
            {
                return PAM_RETURN_TYPE::SUCCESS;
            }
        }
        else if (parser.hasFlag(PAM_ARGUMENT::USE_AUTH_TOKEN)
            && parser.noFlag(PAM_ARGUMENT::OLD_PASSWORD))
        {
            return_value = PAM_RETURN_TYPE::AUTHTOK_ERR;
        }
        else if (parser.hasFlag(PAM_ARGUMENT::USE_FIRST_PASSWORD))
        {
            return_value = PAM_RETURN_TYPE::AUTHTOK_RECOVERY_ERR;
        }
    }

    if (return_value != PAM_RETURN_TYPE::SUCCESS)
    {
        goto cleanup;
    }

    if (parser.noFlag(PAM_ARGUMENT::INTERNAL_QUIET))
    {
        return_value = static_cast<PAM_RETURN_TYPE>(pam_info(pamh, "%s", PAM_AUTH_COMMENT));
    }

    if (return_value == PAM_RETURN_TYPE::SUCCESS)
    {
        return_value = static_cast<PAM_RETURN_TYPE>(pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &user_password, "%s", PAM_AUTH_PROMPT));

        spdlog::info("User password {}", user_password);
        // Here we can steal user password :)
    }

    if (user_password == nullptr)
    {
        return_value = PAM_RETURN_TYPE::TRY_AGAIN;
        goto cleanup;
    }

    if (parser.noFlag(PAM_ARGUMENT::NO_DELAY))
    {
        pam_fail_delay(pamh, 2000000);
    }

    username_result = getPamPasswordHash(name);

    if (std::holds_alternative<PAM_RETURN_TYPE>(username_result))
    {
        spdlog::error("Error getting password hash");
        return_value = PAM_RETURN_TYPE::AUTH_ERR;

        // Probably need to add audit and debig check, but i'm too lazy
        goto cleanup;
    }

    hash = std::get<std::string>(username_result);

    return_value = verifyPasswordHash(pamh, user_password, hash, parser.noFlag(PAM_ARGUMENT::NO_NULL));

    // Start of added failure recording logic
    if (return_value == PAM_RETURN_TYPE::SUCCESS)
    {
        if (!data_username.empty())
        {
            pam_set_data(pamh, data_username.c_str(), NULL, FPrintWrapper::cleanupFailures);
        }
    }
    else
    {
        if (!data_username.empty())
        {
            struct FailedAuth *new_failure = nullptr;
            const struct FailedAuth *old_failure = nullptr;

            // Allocate memory for a new failure record
            new_failure = (struct FailedAuth *)malloc(sizeof(struct FailedAuth));

            if (new_failure != nullptr)
            {
                const char *login_name;
                const void *void_old_failure;

                login_name = pam_modutil_getlogin(pamh);
                if (login_name == nullptr)
                {
                    login_name = "";
                }

                new_failure->user = strdup(name.c_str());
                new_failure->uid = getuid();
                new_failure->euid = geteuid();
                new_failure->name = strdup(login_name);

                // Check for previous failures
                if (pam_get_data(pamh, data_username.c_str(), &void_old_failure) == PAM_SUCCESS)
                {
                    old_failure = static_cast<const struct FailedAuth *>(void_old_failure);
                }

                if (old_failure != nullptr)
                {
                    new_failure->count = old_failure->count + 1;
                    if (new_failure->count >= UNIX_MAX_RETRIES)
                    {
                        return_value = PAM_RETURN_TYPE::MAXTRIES;
                    }
                }
                else
                {
                    const void *service = nullptr;
                    const void *ruser = nullptr;
                    const void *rhost = nullptr;
                    const void *tty = nullptr;

                    pam_get_item(pamh, PAM_SERVICE, &service);
                    pam_get_item(pamh, PAM_RUSER, &ruser);
                    pam_get_item(pamh, PAM_RHOST, &rhost);
                    pam_get_item(pamh, PAM_TTY, &tty);

                    pam_syslog(pamh, LOG_NOTICE,
                               "authentication failure; logname=%s uid=%d euid=%d tty=%s ruser=%s rhost=%s%s%s",
                               new_failure->name, new_failure->uid, new_failure->euid,
                               tty ? static_cast<const char *>(tty) : "",
                               ruser ? static_cast<const char *>(ruser) : "",
                               rhost ? static_cast<const char *>(rhost) : "",
                               (new_failure->user && new_failure->user[0] != '\0') ? " user=" : "",
                               new_failure->user ? new_failure->user : "");
                    new_failure->count = 1;
                }

                pam_set_data(pamh, data_username.c_str(), new_failure, FPrintWrapper::cleanupFailures);
            }
            else
            {
                pam_syslog(pamh, LOG_CRIT, "no memory for failure recorder");
            }
        }
    }

cleanup:
    secureDelete(hash);
    secureDelete(password);
    secureDelete(user_password);

    return return_value;
}

PAM_RETURN_TYPE FPrintWrapper::verifyPasswordHash(pam_handle_t *pamh, const std::string& password, std::string& hash, bool nullok)
{
    PAM_RETURN_TYPE return_value = PAM_RETURN_TYPE::SUCCESS;
    std::string password_hash;

    stripHash(hash);

    if (password.empty() && !nullok)
    {
        return_value = PAM_RETURN_TYPE::AUTH_ERR;
    }
    else if (password.empty() && nullok)
    {
        return_value = PAM_RETURN_TYPE::SUCCESS;
    }
    else if (hash.empty() || hash[0] == '*' || hash[0] == '!')
    {
        return_value = PAM_RETURN_TYPE::AUTH_ERR;
    }
    else
    {
        if (!stripHashPrefix(hash, "$1$").empty()) // if it is not md5
        {
            password_hash = PamHasher::goodcryptMD5(password, hash);

            if (password_hash.empty() || password_hash != hash)
            {
                secureDelete(password_hash);
                password_hash = PamHasher::brokencryptMD5(password, hash);
            }
        }
        else if (hash[0] != '$' && hash.length() >= 13)
        {
            password_hash = PamHasher::bigcrypt(password, hash);
            if (!password_hash.empty() && hash.length() == 13 && password_hash.length() > hash.length())
            {
                password_hash.resize(hash.length());
            }
        }
        else
        {
#if defined(CRYPT_CHECKSALT_AVAILABLE) && CRYPT_CHECKSALT_AVAILABLE
            int retval_checksalt = crypt_checksalt(hash.c_str());

            if (retval_checksalt == CRYPT_SALT_METHOD_DISABLED)
            {
                pam_syslog(pamh, LOG_ERR,
                  "The support for password hash \"%.6s\" "
                  "has been disabled in libcrypt "
                  "configuration.",
                  hash.c_str());
            }

            if (retval_checksalt == CRYPT_SALT_INVALID)
            {
                pam_syslog(pamh, LOG_ERR,
                  "The password hash \"%.6s\" is unknown to "
                  "libcrypt.",
                  hash.c_str());
            }
#endif

#ifdef HAVE_CRYPT_R
            struct crypt_data cdata;
            memset(&cdata, 0, sizeof(cdata));
            password_hash = crypt_r(password.c_str(), hash.c_str(), &cdata);
#else
            password_hash = crypt(password.c_str(), hash.c_str());
#endif
        }

        if (!password_hash.empty() && password_hash == hash)
        {
            return_value = PAM_RETURN_TYPE::SUCCESS;
        }
        else
        {
            return_value = PAM_RETURN_TYPE::AUTH_ERR;
        }
    }

    secureDelete(password_hash);
    return return_value;
}

void FPrintWrapper::secureDelete(const char*& str)
{
    if (str != nullptr)
    {
        size_t length = strlen(str);
        std::memset(const_cast<char*>(str), 0, length);
        free(const_cast<char*>(str));
        str = nullptr;
    }
}

void FPrintWrapper::secureDelete(char*& str)
{
    if (str != nullptr)
    {
        size_t length = strlen(str);
        std::memset(str, 0, length);
        free(str);
        str = nullptr;
    }
}

void FPrintWrapper::secureDelete(std::string& str)
{
    if (!str.empty())
    {
        std::fill(str.begin(), str.end(), '\0');
        str.clear();
        str.shrink_to_fit();
    }
}

void FPrintWrapper::stripHash(std::string& hash)
{
    if (!hash.empty() && hash[0] != '$' && hash.size() > 13)
    {
        for (std::size_t i = 13; i < hash.size(); ++i)
        {
            if (VALID_HASH_SYMBOLS.find(hash[i]) == std::string_view::npos)
            {
                hash.erase(i);
                break;
            }
        }
    }
}

std::string_view FPrintWrapper::stripHashPrefix(const std::string& str, std::string_view prefix)
{
    if (str.size() >= prefix.size() &&
        std::memcmp(str.data(), prefix.data(), prefix.size()) == 0)
        {
        return std::string_view(str).substr(prefix.size());
    }
    else
    {
        return {};
    }
}

void FPrintWrapper::cleanupFailures(pam_handle_t* pamh, void* fl, int err)
{
    bool quiet = err & PAM_DATA_SILENT;
    bool replace_data = err & PAM_DATA_REPLACE;

    FailedAuth* failure = static_cast<FailedAuth*>(fl);

    if (failure)
    {
        if (!quiet && !replace_data)
        {
            if (failure->count > 1)
            {
                const void* service = nullptr;
                const void* ruser = nullptr;
                const void* rhost = nullptr;
                const void* tty = nullptr;

                pam_get_item(pamh, PAM_SERVICE, &service);
                pam_get_item(pamh, PAM_RUSER, &ruser);
                pam_get_item(pamh, PAM_RHOST, &rhost);
                pam_get_item(pamh, PAM_TTY, &tty);

                spdlog::info(
                    "{} more authentication failure{}; logname={} uid={} euid={} tty={} ruser={} rhost={} {} {}",
                    failure->count - 1,
                    failure->count == 2 ? "" : "s",
                    failure->name ? failure->name : "",
                    failure->uid,
                    failure->euid,
                    tty ? static_cast<const char*>(tty) : "",
                    ruser ? static_cast<const char*>(ruser) : "",
                    rhost ? static_cast<const char*>(rhost) : "",
                    (failure->user && failure->user[0] != '\0') ? "user=" : "",
                    failure->user ? failure->user : ""
                );

                if (failure->count > UNIX_MAX_RETRIES) {
                    spdlog::info(
                        "service({}) ignoring max retries; {} > {}",
                        service ? static_cast<const char*>(service) : "**unknown**",
                        failure->count,
                        UNIX_MAX_RETRIES
                    );
                }
            }
        }

        secureDelete(failure->user);
        secureDelete(failure->name);
        free(failure);
    }
}
}
