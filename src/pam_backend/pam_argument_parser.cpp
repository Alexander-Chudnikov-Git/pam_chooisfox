#include "pam_argument_parser.hpp"
#include "pam_globals.hpp"

namespace CHOOI
{
ArgumentParser::ArgumentParser()
{
    unix_args = {
        {PAM_ARGUMENT::OLD_PASSWORD,            {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::OLD_PASSWORD}},
        {PAM_ARGUMENT::VERIFY_PASSWORD,         {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::VERIFY_PASSWORD}},
        {PAM_ARGUMENT::I_AM_ROOT,               {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::I_AM_ROOT}},
        {PAM_ARGUMENT::INTERNAL_PRELIM,         {"",              PAM_MASK::PRELIM_UPDATE,     PAM_FLAGS::INTERNAL_PRELIM}},
        {PAM_ARGUMENT::INTERNAL_UPDATE,         {"",              PAM_MASK::PRELIM_UPDATE,     PAM_FLAGS::INTERNAL_UPDATE}},
        {PAM_ARGUMENT::NO_NULL,                 {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::NO_NULL}},
        {PAM_ARGUMENT::INTERNAL_QUIET,          {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::INTERNAL_QUIET}},

        {PAM_ARGUMENT::AUDIT,                   {"audit",         PAM_MASK::ALL_ON,            PAM_FLAGS::AUDIT}},
        {PAM_ARGUMENT::DEBUG,                   {"debug",         PAM_MASK::ALL_ON,            PAM_FLAGS::DEBUG}},
        {PAM_ARGUMENT::NO_DELAY,                {"nodelay",       PAM_MASK::ALL_ON,            PAM_FLAGS::NO_DELAY}},
        {PAM_ARGUMENT::QUIET,                   {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::QUIET}},

        {PAM_ARGUMENT::USE_FIRST_PASSWORD,      {"use_first_pass",PAM_MASK::FIRST_PASS,        PAM_FLAGS::USE_FIRST_PASSWORD}},
        {PAM_ARGUMENT::TRY_FIRST_PASSWORD,      {"try_first_pass",PAM_MASK::FIRST_PASS,        PAM_FLAGS::TRY_FIRST_PASSWORD}},
        {PAM_ARGUMENT::NOT_SET_PASSWORD,        {"not_set_pass",  PAM_MASK::ALL_ON,            PAM_FLAGS::NOT_SET_PASSWORD}},
        {PAM_ARGUMENT::USE_AUTH_TOKEN,          {"use_authtok",   PAM_MASK::ALL_ON,            PAM_FLAGS::USE_AUTH_TOKEN}},
        {PAM_ARGUMENT::PASSWORD_DONT_EXPIRE,    {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::PASSWORD_DONT_EXPIRE}},
        {PAM_ARGUMENT::SHADOW_FILE,             {"shadow",        PAM_MASK::ALL_ON,            PAM_FLAGS::SHADOW_FILE}},
        {PAM_ARGUMENT::NULL_OK,                 {"nullok",        PAM_MASK::NULLOK,            PAM_FLAGS::NULL_OK}},
        {PAM_ARGUMENT::UNIX_LIKE_AUTH,          {"likeauth",      PAM_MASK::ALL_ON,            PAM_FLAGS::UNIX_LIKE_AUTH}},
        {PAM_ARGUMENT::NO_REAP_CHILD,           {"noreap",        PAM_MASK::ALL_ON,            PAM_FLAGS::NO_REAP_CHILD}},
        {PAM_ARGUMENT::IGNORE_BROKEN_SHADOW,    {"broken_shadow", PAM_MASK::ALL_ON,            PAM_FLAGS::IGNORE_BROKEN_SHADOW}},

        {PAM_ARGUMENT::MD5_PASSWORD,            {"md5",           PAM_MASK::MD5_PASS,          PAM_FLAGS::MD5_PASSWORD}},
        {PAM_ARGUMENT::NIS_PASSWORD,            {"nis",           PAM_MASK::ALL_ON,            PAM_FLAGS::NIS_PASSWORD}},
        {PAM_ARGUMENT::BIG_CRYPT_PASSWORD,      {"bigcrypt",      PAM_MASK::BIGCRYPT,          PAM_FLAGS::BIG_CRYPT_PASSWORD}},
        {PAM_ARGUMENT::SHA256_PASSWORD,         {"sha256",        PAM_MASK::SHA256_PASS,       PAM_FLAGS::SHA256_PASSWORD}},
        {PAM_ARGUMENT::SHA512_PASSWORD,         {"sha512",        PAM_MASK::SHA512_PASS,       PAM_FLAGS::SHA512_PASSWORD}},
        {PAM_ARGUMENT::BLOWFISH_PASSWORD,       {"blowfish",      PAM_MASK::BLOWFISH_PASS,     PAM_FLAGS::BLOWFISH_PASSWORD}},
        {PAM_ARGUMENT::DES_PASSWORD,            {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::DES_PASSWORD}},
        {PAM_ARGUMENT::GHOST_YESCRYPT_PASSWORD, {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::GHOST_YESCRYPT_PASSWORD}},
        {PAM_ARGUMENT::YESCRYPT_PASSWORD,       {"",              PAM_MASK::ALL_ON,            PAM_FLAGS::YESCRYPT_PASSWORD}},

        {PAM_ARGUMENT::HASH_ALGORITHM_ROUNDS,   {"rounds=",       PAM_MASK::ALL_ON,            PAM_FLAGS::HASH_ALGORITHM_ROUNDS}},
        {PAM_ARGUMENT::MINIMUM_PASSWORD_LENGTH, {"minlen=",       PAM_MASK::ALL_ON,            PAM_FLAGS::MINIMUM_PASSWORD_LENGTH}},
        {PAM_ARGUMENT::REMEMBER_PASSWORD,       {"remember=",     PAM_MASK::ALL_ON,            PAM_FLAGS::REMEMBER_PASSWORD}},
    };
}

ArgumentParser::~ArgumentParser()
{
}

PAM_FLAGS ArgumentParser::genControlSequence(int flags, int *remember, int *rounds, int *pass_min_len, int argc, const char **argv)
{
    control_sequence = PAM_FLAGS::DEFAULT;

    if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK))
    {
		setFlag(PAM_ARGUMENT::I_AM_ROOT);
	}

	if (flags & PAM_UPDATE_AUTHTOK)
	{
        setFlag(PAM_ARGUMENT::INTERNAL_UPDATE);
    }

    if (flags & PAM_PRELIM_CHECK)
    {
        setFlag(PAM_ARGUMENT::INTERNAL_PRELIM);
    }

    if (flags & PAM_SILENT)
    {
        setFlag(PAM_ARGUMENT::INTERNAL_QUIET);
    }

    for (int i = 0; i < argc; ++i)
    {
        bool found = false;
        for (const auto& pair : unix_args)
        {
            if (!pair.second.token.empty() && strncmp(argv[i], pair.second.token.c_str(), pair.second.token.length()) == 0)
            {
                setFlag(pair.first);
                found = true;

                if (remember && pair.first == PAM_ARGUMENT::REMEMBER_PASSWORD)
                {
                    if (auto parsedValue = parseInt(argv[i] + 9))
                    {
                        *remember = *parsedValue;
                    }
                    else
                    {
                        *remember = -1;
                    }
                    if (*remember > 400)
                    {
                        *remember = 400;
                    }
                }
                else if (pass_min_len && pair.first == PAM_ARGUMENT::MINIMUM_PASSWORD_LENGTH)
                {
                    if (auto parsedValue = parseInt(argv[i] + 7))
                    {
                        *pass_min_len = *parsedValue;
                    }
                }
                else if (rounds && pair.first == PAM_ARGUMENT::HASH_ALGORITHM_ROUNDS)
                {
                    if (auto parsedValue = parseInt(argv[i] + 7))
                    {
                        *rounds = *parsedValue;
                    }
                }
                break;
            }
        }

        if (!found)
        {
            spdlog::info("Option \"{}\" is not recognized", argv[i]);
        }
    }

    if ((control_sequence & PAM_FLAGS::DES_PASSWORD) == PAM_FLAGS::DES_PASSWORD && pass_min_len && *pass_min_len > 8)
    {
        spdlog::info("Password minlen reset to 8 characters");
        *pass_min_len = 8;
    }

    if (flags & PAM_DISALLOW_NULL_AUTHTOK)
    {
        setFlag(PAM_ARGUMENT::NO_NULL);
    }

    if ((control_sequence & PAM_FLAGS::BLOWFISH_PASSWORD)     == PAM_FLAGS::BLOWFISH_PASSWORD      &&
        (control_sequence & PAM_FLAGS::HASH_ALGORITHM_ROUNDS) != PAM_FLAGS::HASH_ALGORITHM_ROUNDS)
    {
        *rounds = 5;
        setFlag(PAM_ARGUMENT::HASH_ALGORITHM_ROUNDS);
    }

    if ((control_sequence & PAM_FLAGS::HASH_ALGORITHM_ROUNDS) == PAM_FLAGS::HASH_ALGORITHM_ROUNDS)
    {
        if ((control_sequence & PAM_FLAGS::BLOWFISH_PASSWORD) == PAM_FLAGS::BLOWFISH_PASSWORD)
        {
            if (*rounds < 4 || *rounds > 31)
            {
                *rounds = 5;
            }
        }
        else if (((control_sequence & PAM_FLAGS::SHA256_PASSWORD) == PAM_FLAGS::SHA256_PASSWORD) ||
                 ((control_sequence & PAM_FLAGS::SHA512_PASSWORD) == PAM_FLAGS::SHA512_PASSWORD))
        {
            if (*rounds < 1000)
            {
                unsetFlag(PAM_ARGUMENT::HASH_ALGORITHM_ROUNDS);
            }

            if (*rounds >= 10000000)
            {
                *rounds = 9999999;
            }
        }
    }

    if ((control_sequence & PAM_FLAGS::AUDIT) == PAM_FLAGS::AUDIT)
    {
        setFlag(PAM_ARGUMENT::DEBUG);
    }

    return control_sequence;
}

bool ArgumentParser::hasFlag(PAM_ARGUMENT argument)
{
    const auto& argument_info = unix_args[argument];

    return static_cast<bool>(argument_info.flag & control_sequence);
}

bool ArgumentParser::noFlag(PAM_ARGUMENT argument)
{
    return !hasFlag(argument);
}

void ArgumentParser::setFlag(PAM_ARGUMENT argument)
{
    const auto& argument_info = unix_args[argument];

    control_sequence = (control_sequence & argument_info.mask) | argument_info.flag;
}

void ArgumentParser::unsetFlag(PAM_ARGUMENT argument)
{
    const auto& argument_info = unix_args[argument];

    control_sequence &= ~(argument_info.flag);
}

std::optional<int> ArgumentParser::parseInt(const std::string& string)
{
    try
    {
        size_t pos;
        int value = std::stoi(string, &pos);
        if (pos != string.length())
        {
            return std::nullopt;
        }
        return value;
    }
    catch (const std::out_of_range&)
    {
        return std::nullopt;
    }
    catch (const std::invalid_argument&)
    {
        return std::nullopt;
    }
}

}

