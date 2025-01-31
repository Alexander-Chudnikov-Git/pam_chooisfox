set(CURRENT_LIBRARY_NAME pam_backend)

set(PAM_BACKEND_SRC_DIR "${PAM_CHOOISFOX_MAIN_SRC_DIR}/${CURRENT_LIBRARY_NAME}")

file(GLOB PAM_BACKEND_SRC_FILES CONFIGURE_DEPENDS
    "${PAM_BACKEND_SRC_DIR}/*.hpp"
    "${PAM_BACKEND_SRC_DIR}/*.cpp"
)

source_group("Pam base" FILES ${PAM_CHOOISFOX_LOGGER_SRC_FILES})

add_library(${CURRENT_LIBRARY_NAME} STATIC ${PAM_BACKEND_SRC_FILES})

target_include_directories(${CURRENT_LIBRARY_NAME} PUBLIC ${PAM_CHOOISFOX_INCLUDE_DIRS})
target_link_directories(${CURRENT_LIBRARY_NAME}    PUBLIC ${PAM_CHOOISFOX_INCLUDE_DIRS})
target_link_libraries(${CURRENT_LIBRARY_NAME}             ${PAM_CHOOISFOX_LIBRARIES_LIST})

list(APPEND PAM_CHOOISFOX_INCLUDE_DIRS ${PAM_BACKEND_SRC_DIR})
list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST ${CURRENT_LIBRARY_NAME})
