#ifndef PAM_GLOBALS_HPP
#define PAM_GLOBALS_HPP

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include <type_traits>
#include <cstdint>

#define UNUSED(x) (void)(x)

namespace CHOOI
{
enum class PAM_RETURN_TYPE : std::uint32_t
{
    SUCCESS               = PAM_SUCCESS,
    OPEN_ERR              = PAM_OPEN_ERR,
    SYMBOL_ERR            = PAM_SYMBOL_ERR,
    SERVICE_ERR           = PAM_SERVICE_ERR,
    SYSTEM_ERR            = PAM_SYSTEM_ERR,
    BUF_ERR               = PAM_BUF_ERR,
    PERM_DENIED           = PAM_PERM_DENIED,
    AUTH_ERR              = PAM_AUTH_ERR,
    CRED_INSUFFICIENT     = PAM_CRED_INSUFFICIENT,
    AUTHINFO_UNAVAIL      = PAM_AUTHINFO_UNAVAIL,
    USER_UNKNOWN          = PAM_USER_UNKNOWN,
    MAXTRIES              = PAM_MAXTRIES,
    NEW_AUTHTOK_REQD      = PAM_NEW_AUTHTOK_REQD,
    ACCT_EXPIRED          = PAM_ACCT_EXPIRED,
    SESSION_ERR           = PAM_SESSION_ERR,
    CRED_UNAVAIL          = PAM_CRED_UNAVAIL,
    CRED_EXPIRED          = PAM_CRED_EXPIRED,
    CRED_ERR              = PAM_CRED_ERR,
    NO_MODULE_DATA        = PAM_NO_MODULE_DATA,
    CONV_ERR              = PAM_CONV_ERR,
    AUTHTOK_ERR           = PAM_AUTHTOK_ERR,
    AUTHTOK_RECOVERY_ERR  = PAM_AUTHTOK_RECOVERY_ERR,
    AUTHTOK_LOCK_BUSY     = PAM_AUTHTOK_LOCK_BUSY,
    AUTHTOK_DISABLE_AGING = PAM_AUTHTOK_DISABLE_AGING,
    TRY_AGAIN             = PAM_TRY_AGAIN,
    IGNORE                = PAM_IGNORE,
    ABORT                 = PAM_ABORT,
    AUTHTOK_EXPIRED       = PAM_AUTHTOK_EXPIRED,
    MODULE_UNKNOWN        = PAM_MODULE_UNKNOWN,
    BAD_ITEM              = PAM_BAD_ITEM,
    CONV_AGAIN            = PAM_CONV_AGAIN,
    INCOMPLETE            = PAM_INCOMPLETE,
    COUNT                 = _PAM_RETURN_VALUES
};

enum class PAM_HANDLE_TYPE : std::uint32_t
{
    INVALID      = 0,
    SERVICE      = PAM_SERVICE,
    USER         = PAM_USER,
    TTY          = PAM_TTY,
    RHOST        = PAM_RHOST,
    CONV         = PAM_CONV,
    AUTHTOK      = PAM_AUTHTOK,
    OLDAUTHTOK   = PAM_OLDAUTHTOK,
    RUSER        = PAM_RUSER,
    USER_PROMPT  = PAM_USER_PROMPT,
    FAIL_DELAY   = PAM_FAIL_DELAY,
    XDISPLAY     = PAM_XDISPLAY,
    XAUTHDATA    = PAM_XAUTHDATA,
    AUTHTOK_TYPE = PAM_AUTHTOK_TYPE,
    COUNT
};

enum class PAM_MODULE_TYPE : std::uint32_t
{
    INVALID       = 0,
    AUTHENTICATE  = 1,
    SETCRED       = 2,
    ACCT_MGMT     = 3,
    OPEN_SESSION  = 4,
    CLOSE_SESSION = 5,
    CHAUTHTOK     = 6,
    COUNT         = 7
};

enum class PAM_ARGUMENT : std::uint32_t
{
    OLD_PASSWORD            = 0,  // UNIX__OLD_PASSWD
    VERIFY_PASSWORD         = 1,  // UNIX__VERIFY_PASSWD
    I_AM_ROOT               = 2,  // UNIX__IAMROOT
    AUDIT                   = 3,  // UNIX_AUDIT
    USE_FIRST_PASSWORD      = 4,  // UNIX_USE_FIRST_PASS
    TRY_FIRST_PASSWORD      = 5,  // UNIX_TRY_FIRST_PASS
    NOT_SET_PASSWORD        = 6,  // UNIX_NOT_SET_PASS
    INTERNAL_PRELIM         = 7,  // UNIX__PRELIM
    INTERNAL_UPDATE         = 8,  // UNIX__UPDATE
    NO_NULL                 = 9,  // UNIX__NONULL
    INTERNAL_QUIET          = 10, // UNIX__QUIET
    USE_AUTH_TOKEN          = 11, // UNIX_USE_AUTHTOK
    SHADOW_FILE             = 12, // UNIX_SHADOW
    MD5_PASSWORD            = 13, // UNIX_MD5_PASS
    NULL_OK                 = 14, // UNIX__NULLOK
    DEBUG                   = 15, // UNIX_DEBUG
    NO_DELAY                = 16, // UNIX_NODELAY
    NIS_PASSWORD            = 17, // UNIX_NIS
    BIG_CRYPT_PASSWORD      = 18, // UNIX_BIGCRYPT
    UNIX_LIKE_AUTH          = 19, // UNIX_LIKE_AUTH
    REMEMBER_PASSWORD       = 20, // UNIX_REMEMBER_PASSWD
    NO_REAP_CHILD           = 21, // UNIX_NOREAP
    IGNORE_BROKEN_SHADOW    = 22, // UNIX_BROKEN_SHADOW
    SHA256_PASSWORD         = 23, // UNIX_SHA256_PASS
    SHA512_PASSWORD         = 24, // UNIX_SHA512_PASS
    HASH_ALGORITHM_ROUNDS   = 25, // UNIX_ALGO_ROUNDS
    BLOWFISH_PASSWORD       = 26, // UNIX_BLOWFISH_PASS
    MINIMUM_PASSWORD_LENGTH = 27, // UNIX_MIN_PASS_LEN
    QUIET                   = 28, // UNIX_QUIET
    PASSWORD_DONT_EXPIRE    = 29, // UNIX_NO_PASS_EXPIRY
    DES_PASSWORD            = 30, // UNIX_DES
    GHOST_YESCRYPT_PASSWORD = 31, // UNIX_GOST_YESCRYPT_PASS
    YESCRYPT_PASSWORD       = 32, // UNIX_YESCRYPT_PASS
    ALLOW_EMPTY_PASSWORD    = 33, // UNIX_NULLRESETOK
    COUNT                   = 34 // UNIX_CTRLS_
};

enum class PAM_MASK : std::uint32_t
{
    ALL_ON               = ~0U,
    FIRST_PASS           = ALL_ON ^ 060,
    PRELIM_UPDATE        = ALL_ON ^ 0600,
    MD5_PASS             = ALL_ON ^ 0260420000,
    NULLOK               = ALL_ON ^ 01000,
    BIGCRYPT             = ALL_ON ^ 0260420000,
    SHA256_PASS          = ALL_ON ^ 0260420000,
    SHA512_PASS          = ALL_ON ^ 0260420000,
    BLOWFISH_PASS        = ALL_ON ^ 0260420000,
};

enum class PAM_FLAGS : std::uint32_t
{
    OLD_PASSWORD          = 0x01,
    VERIFY_PASSWORD       = 0x02,
    I_AM_ROOT             = 0x04,
    AUDIT                 = 0x08,
    USE_FIRST_PASSWORD    = 0x10,
    TRY_FIRST_PASSWORD    = 0x20,
    NOT_SET_PASSWORD      = 0x40,
    INTERNAL_PRELIM       = 0x80,
    INTERNAL_UPDATE       = 0x100,
    NO_NULL               = 0x200,
    INTERNAL_QUIET        = 0x400,
    USE_AUTH_TOKEN        = 0x800,
    SHADOW_FILE           = 0x1000,
    MD5_PASSWORD          = 0x2000,
    NULL_OK               = 0x00,
    DEBUG                 = 0x4000,
    NO_DELAY              = 0x8000,
    NIS_PASSWORD          = 0x10000,
    BIG_CRYPT_PASSWORD    = 0x20000,
    UNIX_LIKE_AUTH        = 0x40000,
    REMEMBER_PASSWORD     = 0x80000,
    NO_REAP_CHILD         = 0x100000,
    IGNORE_BROKEN_SHADOW  = 0x200000,
    SHA256_PASSWORD       = 0x400000,
    SHA512_PASSWORD       = 0x800000,
    HASH_ALGORITHM_ROUNDS = 0x1000000,
    BLOWFISH_PASSWORD     = 0x2000000,
    MINIMUM_PASSWORD_LENGTH = 0x4000000,
    QUIET                 = 0x8000000,
    PASSWORD_DONT_EXPIRE  = 0x10000000,
    DES_PASSWORD          = 0x20000000,
    GHOST_YESCRYPT_PASSWORD = 0x40000000,
    YESCRYPT_PASSWORD     = 0x80000000,

    DEFAULT = NO_NULL
};


constexpr PAM_ARGUMENT operator~(PAM_ARGUMENT arg)
{
    return static_cast<PAM_ARGUMENT>(~static_cast<std::uint32_t>(arg));
}

constexpr PAM_FLAGS operator&(PAM_FLAGS a, PAM_FLAGS b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

constexpr PAM_FLAGS operator|(PAM_FLAGS a, PAM_FLAGS b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

constexpr PAM_FLAGS operator^(PAM_FLAGS a, PAM_FLAGS b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) ^  static_cast<std::uint32_t>(b));
}

constexpr PAM_FLAGS operator&(PAM_FLAGS a, PAM_MASK b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

constexpr PAM_FLAGS operator|(PAM_FLAGS a, PAM_MASK b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

constexpr PAM_FLAGS operator^(PAM_FLAGS a, PAM_MASK b)
{
    return static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) ^  static_cast<std::uint32_t>(b));
}
constexpr PAM_FLAGS operator~(PAM_FLAGS a)
{
    return static_cast<PAM_FLAGS>(~static_cast<std::uint32_t>(a));
}

constexpr PAM_FLAGS& operator&=(PAM_FLAGS& a, PAM_FLAGS b)
{
    a = a & b;
    return a;
}

constexpr PAM_FLAGS& operator|=(PAM_FLAGS& a, PAM_FLAGS b)
{
    a = a | b;
    return a;
}

constexpr PAM_FLAGS& operator&=(PAM_FLAGS& a, std::uint32_t b)
{
    a = static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) & b);
    return a;
}

constexpr PAM_FLAGS& operator|=(PAM_FLAGS& a, std::uint32_t b)
{
    a = static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) | b);
    return a;
}

constexpr PAM_FLAGS& operator&=(PAM_FLAGS& a, PAM_MASK b)
{
    a = static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
    return a;
}

constexpr PAM_FLAGS& operator|=(PAM_FLAGS& a, PAM_MASK b)
{
    a = static_cast<PAM_FLAGS>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
    return a;
}
}

#endif // PAM_GLOBALS_HPP
