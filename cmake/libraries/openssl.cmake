find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST OpenSSL::SSL OpenSSL::Crypto)
