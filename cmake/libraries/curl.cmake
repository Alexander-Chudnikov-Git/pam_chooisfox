find_package(CURL REQUIRED)

include_directories(${CURL_INCLUDE_DIR})

list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST ${CURL_LIBRARIES})

