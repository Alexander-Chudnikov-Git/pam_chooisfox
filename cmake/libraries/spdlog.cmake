FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.0
)
FetchContent_MakeAvailable(spdlog)

list(APPEND PAM_CHOOISFOX_LIBRARIES_LIST spdlog::spdlog)

target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ENABLE_SYSLOG)

