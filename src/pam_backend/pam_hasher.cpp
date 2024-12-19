#include "pam_hasher.hpp"

#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/syslog_sink.h>
#include <spdlog/pattern_formatter.h>

namespace CHOOI
{
std::string PamHasher::goodcryptMD5(const std::string& password, const std::string& hash)
{
    std::string_view hash_view(hash);
    size_t first_dollar = hash_view.find('$');
    size_t second_dollar = hash_view.find('$', first_dollar + 1);
    size_t third_dollar = hash_view.find('$', second_dollar + 1);

    if (first_dollar == std::string_view::npos || second_dollar == std::string_view::npos || third_dollar == std::string_view::npos)
    {
        spdlog::error("Invalid hash format");
        return "";
    }

    std::string salt = hash.substr(0, third_dollar + 1);

    unsigned char digest[MD5_DIGEST_LENGTH];
    const EVP_MD* md5 = EVP_md5();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        spdlog::error("EVP_MD_CTX_new failed");
        return "";
    }

    if (EVP_DigestInit_ex(ctx, md5, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestInit_ex failed");
        return "";
    }

    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (password)");
        return "";
    }

    if (EVP_DigestUpdate(ctx, salt.c_str(), salt.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (salt)");
        return "";
    }

    if (EVP_DigestFinal_ex(ctx, digest, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestFinal_ex failed");
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }

    std::string computed_hash = salt + ss.str();

    return computed_hash;
}

std::string PamHasher::brokencryptMD5(const std::string& password, const std::string& hash)
{
    // 1. Extract the salt from the hash.
    std::string_view hash_view(hash);
    size_t first_dollar = hash_view.find('$');
    size_t second_dollar = hash_view.find('$', first_dollar + 1);
    size_t third_dollar = hash_view.find('$', second_dollar + 1);

    if (first_dollar == std::string_view::npos || second_dollar == std::string_view::npos || third_dollar == std::string_view::npos)
    {
        spdlog::error("Invalid hash format");
        return "";
    }

    std::string salt = hash.substr(0, third_dollar + 1);
    std::string extracted_hash = hash.substr(third_dollar + 1);

    // 2. Compute an initial MD5 hash (H1) of the password and salt.
    unsigned char h1_digest[MD5_DIGEST_LENGTH];
    const EVP_MD* md5 = EVP_md5();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        spdlog::error("EVP_MD_CTX_new failed");
        return "";
    }

    if (EVP_DigestInit_ex(ctx, md5, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestInit_ex failed");
        return "";
    }

    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (password)");
        return "";
    }

    if (EVP_DigestUpdate(ctx, salt.c_str(), salt.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (salt)");
        return "";
    }

    if (EVP_DigestFinal_ex(ctx, h1_digest, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestFinal_ex failed");
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // 3. Compute an alternate MD5 hash (A1) of password, salt and password again
    unsigned char a1_digest[MD5_DIGEST_LENGTH];
    ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        spdlog::error("EVP_MD_CTX_new failed");
        return "";
    }

    if (EVP_DigestInit_ex(ctx, md5, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestInit_ex failed");
        return "";
    }

    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (password)");
        return "";
    }

    if (EVP_DigestUpdate(ctx, salt.c_str(), salt.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (salt)");
        return "";
    }

    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (password)");
        return "";
    }

    if (EVP_DigestFinal_ex(ctx, a1_digest, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestFinal_ex failed");
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // 4. Create a new buffer and update it with specific portions of H1, A1, and the password.
    std::vector<unsigned char> buffer;
    for (size_t i = password.length(); i > 0; i -= 16)
    {
        size_t update_len = std::min((size_t)16, i);
        buffer.insert(buffer.end(), &a1_digest[0], &a1_digest[0] + update_len);
    }

    for (size_t i = password.length(); i > 0; i >>= 1)
    {
        if (i & 1)
        {
            buffer.push_back(0);
        }
        else
        {
            buffer.push_back(password[0]);
        }
    }

    // 5. Compute the MD5 hash (H2) of the buffer.
    unsigned char h2_digest[MD5_DIGEST_LENGTH];
    ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        spdlog::error("EVP_MD_CTX_new failed");
        return "";
    }

    if (EVP_DigestInit_ex(ctx, md5, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestInit_ex failed");
        return "";
    }

    if (EVP_DigestUpdate(ctx, buffer.data(), buffer.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (buffer)");
        return "";
    }

    if (EVP_DigestFinal_ex(ctx, h2_digest, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestFinal_ex failed");
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // 6. Perform 1000 rounds of MD5 calculations based on previous results and password/salt.
    for (int round = 0; round < 1000; ++round)
    {
        ctx = EVP_MD_CTX_new();

        if (ctx == nullptr)
        {
            spdlog::error("EVP_MD_CTX_new failed");
            return "";
        }

        if (EVP_DigestInit_ex(ctx, md5, nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            spdlog::error("EVP_DigestInit_ex failed");
            return "";
        }

        if (round & 1)
        {
            if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (password)");
                return "";
            }
        }
        else
        {
            if (EVP_DigestUpdate(ctx, h2_digest, MD5_DIGEST_LENGTH) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (h2_digest)");
                return "";
            }
        }

        if (round % 3)
        {
            if (EVP_DigestUpdate(ctx, salt.c_str(), salt.length()) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (salt)");
                return "";
            }
        }

        if (round % 7)
        {
            if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (password)");
                return "";
            }
        }

        if (!(round & 1))
        {
            if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (password)");
                return "";
            }
        }
        else
        {
            if (EVP_DigestUpdate(ctx, h2_digest, MD5_DIGEST_LENGTH) != 1)
            {
                EVP_MD_CTX_free(ctx);
                spdlog::error("EVP_DigestUpdate failed (h2_digest)");
                return "";
            }
        }

        if (EVP_DigestFinal_ex(ctx, h2_digest, nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            spdlog::error("EVP_DigestFinal_ex failed");
            return "";
        }

        EVP_MD_CTX_free(ctx);
    }

    // 7. Rearrange specific bytes from the final digest (h2_digest).
    unsigned char final_digest[16] = {
        h2_digest[0], h2_digest[6], h2_digest[12],
        h2_digest[1], h2_digest[7], h2_digest[13],
        h2_digest[2], h2_digest[8], h2_digest[14],
        h2_digest[3], h2_digest[9], h2_digest[15],
        h2_digest[4], h2_digest[10], h2_digest[5],
        h2_digest[11]
    };

    // 8. Convert the final digest to a base64-like string.
    static const char* itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string base64_result;

    auto append_group = [&](int b1, int b2, int b3, int count)
    {
        int value = (b1 << 16) | (b2 << 8) | b3;
        for (int i = 0; i < count; ++i)
        {
            base64_result += itoa64[value & 0x3f];
            value >>= 6;
        }
    };

    append_group(final_digest[0], final_digest[1], final_digest[2], 4);
    append_group(final_digest[3], final_digest[4], final_digest[5], 4);
    append_group(final_digest[6], final_digest[7], final_digest[8], 4);
    append_group(final_digest[9], final_digest[10], final_digest[11], 4);
    append_group(final_digest[12], final_digest[13], final_digest[14], 4);
    append_group(0, 0, final_digest[15], 2);

    // 9. Combine salt and the base64-like string.
    std::string computed_hash = salt + base64_result;

    return computed_hash;
}
std::string PamHasher::bigcrypt(const std::string& password, const std::string& salt)
{
    if (salt.length() < 2)
    {
        spdlog::error("bigcrypt: Salt must be at least 2 characters long");
        return "";
    }

    // 1. Extract the first 2 characters of the salt.
    std::string two_char_salt = salt.substr(0, 2);

    // 2. Compute SHA256 hash of the password.
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    const EVP_MD* sha256 = EVP_sha256();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        spdlog::error("EVP_MD_CTX_new failed");
        return "";
    }

    if (EVP_DigestInit_ex(ctx, sha256, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestInit_ex failed");
        return "";
    }

    if (EVP_DigestUpdate(ctx, password.c_str(), password.length()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestUpdate failed (password)");
        return "";
    }

    if (EVP_DigestFinal_ex(ctx, sha256_digest, nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        spdlog::error("EVP_DigestFinal_ex failed");
        return "";
    }

    EVP_MD_CTX_free(ctx);

    // 3. Truncate the SHA256 digest to 24 bytes (192 bits).
    if (SHA256_DIGEST_LENGTH < 24)
    {
        spdlog::error("SHA256 digest is too short for bigcrypt");
        return "";
    }
    unsigned char truncated_digest[24];
    std::memcpy(truncated_digest, sha256_digest, 24);

    // 4. Encode the truncated digest using a modified base64 encoding.
    static const char* itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string base64_result;

    auto append_group = [&](int b1, int b2, int b3, int count)
    {
        int value = (b1 << 16) | (b2 << 8) | b3;
        for (int i = 0; i < count; ++i)
        {
            base64_result += itoa64[value & 0x3f];
            value >>= 6;
        }
    };

    for (int i = 0; i < 24; i += 3)
    {
        append_group(truncated_digest[i],
                     i + 1 < 24 ? truncated_digest[i + 1] : 0,
                     i + 2 < 24 ? truncated_digest[i + 2] : 0,
                     4);
    }

    // 5. Concatenate the 2-character salt and the encoded result.
    std::string computed_hash = two_char_salt + base64_result;

    return computed_hash;
}

}
