include(FetchContent)
find_package(PkgConfig REQUIRED)

message(STATUS "CXX compiler:      ${CMAKE_CXX_COMPILER_ID}")

if(NOT CMAKE_RELEASE)
	set(CMAKE_CXX_FLAGS    "${CMAKE_CXX_FLAGS} -g")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS}")
endif()

# [INCLUDE DIRECTORIES]
set(PAM_CHOOISFOX_INCLUDE_DIRS)

# [LIBRARIES LIST]
set(PAM_CHOOISFOX_LIBRARIES_LIST)

# [SOURCE DIRECTORIES]
set(PAM_CHOOISFOX_MAIN_SRC_DIR   "src")

file(GLOB PAM_CHOOISFOX_MAIN_SRC_FILES CONFIGURE_DEPENDS
    "${PAM_CHOOISFOX_MAIN_SRC_DIR}/*.hpp"
    "${PAM_CHOOISFOX_MAIN_SRC_DIR}/*.cpp"
)

# [SOURCE GROUPS]
source_group("Main" FILES ${PAM_CHOOISFOX_MAIN_SRC_FILES})

list(APPEND PAM_CHOOISFOX_INCLUDE_DIRS ${PAM_CHOOISFOX_MAIN_SRC_DIR})

# LINUX does not exclude MACOS
if(MACOS)
    message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
elseif(LINUX)
    include(cmake/platform/linux_builder.cmake)
else()
    message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
endif()

# [LIBRARIES]
include(cmake/libraries/curl.cmake)
include(cmake/libraries/fmt.cmake)
include(cmake/libraries/spdlog.cmake)
include(cmake/libraries/openssl.cmake)
include(cmake/libraries/libxcrypt.cmake)
include(cmake/libraries/dbus.cmake)
include(cmake/libraries/glib2.cmake)
include(cmake/libraries/pam_backend.cmake)

target_include_directories(${PROJECT_NAME} PUBLIC ${PAM_CHOOISFOX_INCLUDE_DIRS})
target_link_directories(${PROJECT_NAME}    PUBLIC ${PAM_CHOOISFOX_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}             ${PAM_CHOOISFOX_LIBRARIES_LIST})

set_target_properties(${PROJECT_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN 1
)

if(CMAKE_RELEASE)
    add_compile_definitions(CMAKE_RELEASE)
endif()

include(cmake/utils/upx_compress.cmake)
