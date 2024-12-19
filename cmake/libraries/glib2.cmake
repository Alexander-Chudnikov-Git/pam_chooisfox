pkg_check_modules(GLIB REQUIRED glib-2.0)

include_directories(${GLIB_INCLUDE_DIRS})

list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST ${GLIB_LIBRARIES})

