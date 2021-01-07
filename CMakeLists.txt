cmake_minimum_required(VERSION 3.13)
project(optee_engine NONE)
include(ExternalProject)

enable_language(C)
enable_language(CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "~/.cmake/Modules")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(OPTEE_ENGINE_INSTALL_DIR /opt)

# OP-TEE
if (NOT OPTEE_BUILD_DIR)
    message(FATAL_ERROR "Must specify -DOPTEE_BUILD_DIR")
endif()
if (NOT PLATFORM)
    message(FATAL_ERROR "Must specify -DPLATFORM=V where V is either qemu or hikey960")
endif()
set(OPTEE_ROOT_DIR ${OPTEE_BUILD_DIR})
set(OPTEE_REE_LIB_DIR ${OPTEE_ROOT_DIR}/out-br/target/usr/lib)
set(OPTEE_REE_INCLUDE_DIR ${OPTEE_ROOT_DIR}/optee_client/public)
set(CMAKE_C_COMPILER ${OPTEE_ROOT_DIR}/toolchains/aarch64/bin/aarch64-linux-gnu-gcc CACHE PATH "" FORCE)
set(CMAKE_CXX_COMPILER ${OPTEE_ROOT_DIR}/toolchains/aarch64/bin/aarch64-linux-gnu-g++ CACHE PATH "" FORCE)

# 3rd Parties

# OpenSSL config targets
set(OPENSSL_CONFIG_CMD "Configure" CACHE STRING "Command used to configure OpenSSL (default ./config)")
set(OPENSSL_CONFIG_TARGET "linux-aarch64" CACHE STRING "Platform for which OpenSSL should be compiled (default native)")

add_subdirectory(3rd/openssl-cmake)
# Gtest
add_subdirectory(3rd/gtest)
get_property(OPENSSL_INSTALL_DIR GLOBAL PROPERTY openssl_build_install_dir_property)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)

# Trusted Application sources
set(TA_DELEGATOR_ROOT ${CMAKE_SOURCE_DIR}/src/ta)

# Global configuration
set(C_CXX_FLAGS "\
    -Wno-ignored-qualifiers \
    -Wpedantic \
    -Wall \
    -Werror \
    -Wshadow \
    -Wno-variadic-macros \
    -Wundef \
    -Wunused-result")

# Control Debug/Release mode
IF(${CMAKE_BUILD_TYPE} MATCHES "Debug")
	set(C_CXX_FLAGS "${C_CXX_FLAGS} -g3 -O0 -Wno-unused")
else()
	set(C_CXX_FLAGS "${C_CXX_FLAGS} -O3")
endif()

set(CMAKE_C_FLAGS ${C_CXX_FLAGS})
set(CMAKE_CXX_FLAGS ${C_CXX_FLAGS})

# --- Build targets ---

# lang specific settings
set(CMAKE_C_FLAGS
	"${CMAKE_C_FLAGS} \
	-std=gnu99 \
	-Werror=implicit-function-declaration \
	-Wmissing-prototypes \
	-Wstrict-prototypes")

# optee_eng
set(OPTEE_ENGINE_SRC
    src/optee_engine/back.c
    src/optee_engine/front.c
    src/optee_engine/log.c
)

add_library(
    optee_eng SHARED
    ${OPTEE_ENGINE_SRC}
)

target_include_directories(
    optee_eng PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${OPTEE_REE_INCLUDE_DIR}
    src
)

target_include_directories(
    optee_eng PUBLIC
    inc
    ${OPENSSL_INCLUDE_DIR}
    ${TA_DELEGATOR_ROOT}/include
)

target_link_directories(
	optee_eng PRIVATE
    ${OPTEE_REE_LIB_DIR})

target_link_libraries(
    optee_eng
    OpenSSL_crypto_shared
    teec
    ${CMAKE_DL_LIBS})

IF(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(optee_eng PRIVATE BUILD_DEBUG)
endif()

# Key management app
add_executable(
    optee_keymgnt
    src/optee_engine/keymgnt.c
)
target_include_directories(
    optee_keymgnt PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${OPTEE_REE_INCLUDE_DIR}
    ${TA_DELEGATOR_ROOT}/include)
target_link_directories(
    optee_keymgnt PRIVATE
    ${OPTEE_REE_LIB_DIR})
target_link_libraries(
    optee_keymgnt
    OpenSSL_crypto_shared
    teec
    ${OPTEE_ENG_LD_FLAGS}
    ${CMAKE_DL_LIBS})

ExternalProject_Add(optee_eng_ta
    SOURCE_DIR ${TA_DELEGATOR_ROOT}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND OPTEE_ROOT=${OPTEE_BUILD_DIR} O=${CMAKE_CURRENT_BINARY_DIR} ${MAKE_PROGRAM}
    BUILD_IN_SOURCE TRUE
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/ta
    INSTALL_COMMAND ""
    BUILD_ALWAYS TRUE
)

# Google benchmark settings
set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
# Target for benchmark - it also builds gtest library
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Enable testing of the benchmark library." FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
set(GOOGLETEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/3rd/gtest" CACHE PATH "Path to the gtest sources" FORCE)
set(BENCHMARK_OS_WINDOWS OFF CACHE BOOL "" FORCE)
set(HAVE_POSIX_REGEX OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_EXCEPTIONS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(3rd/gbench)
add_executable(
    speed
    src/optee_engine/speed.cc)
target_include_directories(
    speed PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(
    speed
    gtest
    pthread
    OpenSSL_crypto_shared
    benchmark::benchmark)

# Install copies needed files to the buildroot overlay.

# OpenVPN config
install(FILES ${PROJECT_SOURCE_DIR}/cfg/openvpn_cli.conf
    DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/etc/openvpn/
    RENAME client.conf)
install(FILES
    ${PROJECT_SOURCE_DIR}/cfg/certs/ca.cert
    ${PROJECT_SOURCE_DIR}/cfg/certs/client.cert
    ${PROJECT_SOURCE_DIR}/cfg/certs/client.key
    DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/etc/openvpn/certs/)
# OpenSSL config
install(FILES ${PROJECT_SOURCE_DIR}/cfg/openssl_optee.cnf
    DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/etc/ssl/
    RENAME openssl.cnf)
# OpTEE engine
install(TARGETS optee_eng
    LIBRARY DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/opt/
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
# TA
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/8aaaf200-2450-11e4-0060-0dc0ffee0000.ta
    DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/lib/optee_armtz)
# Must be empty and have same name as the TEE key ID
install(FILES /dev/null
    DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/etc/openvpn/
    RENAME vpn.testlab.com)
# Key management app
install(TARGETS optee_keymgnt
    RUNTIME DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/usr/bin/
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ)
# Speed app
install(TARGETS speed
    RUNTIME DESTINATION ${OPTEE_ROOT_DIR}/build/br-ext/board/${PLATFORM}/overlay/usr/bin/
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ)
