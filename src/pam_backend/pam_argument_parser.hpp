#ifndef PAM_ARGUMENT_PARSER_HPP
#define PAM_ARGUMENT_PARSER_HPP

#include "pam_globals.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/pattern_formatter.h>

#include <optional>
#include <string>
#include <cstring>
#include <map>

#include <unistd.h>

namespace CHOOI
{
class ArgumentParser
{
public:
    struct Option
    {
        std::string token;
        PAM_MASK    mask;
        PAM_FLAGS   flag;
    };

public:
    ArgumentParser();
    ~ArgumentParser();

    PAM_FLAGS genControlSequence(int flags, int *remember, int *rounds, int *pass_min_len, int argc, const char **argv);

    bool hasFlag(PAM_ARGUMENT argument);
    bool noFlag(PAM_ARGUMENT argument);

private:
    void setFlag(PAM_ARGUMENT flag);
    void unsetFlag(PAM_ARGUMENT flag);

    std::optional<int> parseInt(const std::string& string);

private:
    std::map<PAM_ARGUMENT, Option> unix_args;

    PAM_FLAGS control_sequence;
};
}

#endif // PAM_ARGUMENT_PARSER_HPP
