find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXCRYPT REQUIRED libxcrypt)

include_directories(${LIBXCRYPT_INCLUDE_DIRS})

list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST ${LIBXCRYPT_LIBRARIES})

