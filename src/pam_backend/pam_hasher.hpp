#ifndef PAM_HASHER_HPP
#define PAM_HASHER_HPP

#include <string>

#include <crypt.h>

namespace CHOOI
{
class PamHasher
{
public:
    static std::string goodcryptMD5(const std::string& password, const std::string& hash);
    static std::string brokencryptMD5(const std::string& password, const std::string& hash);
    static std::string bigcrypt(const std::string& password, const std::string& salt);
};
}

#endif // PAM_HASHER_HPP
