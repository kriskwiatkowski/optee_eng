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
set(OPTEE_ENGINE_INSTALL_DIR /usr/local/softs)

# --- Configuration ---

# Arch settings
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CLANG 1)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
   set(CMAKE_C_COMPILER /usr/bin/cc CACHE PATH "" FORCE)
   set(CMAKE_CXX_COMPILER /usr/bin/c++ CACHE PATH "" FORCE)
   set(OPTEE_ENG_LD_FLAGS "-Wl")
else()
   set(OPTEE_ENG_LD_FLAGS "-W")
endif()

# Build OpenSSL if not provided, otherwise define
# OpenSSL_ssl_shared and OpenSSL_crypto_shared
if (BUILD_OPENSSL)
	add_subdirectory(3rd/openssl-cmake)
else()
	if (NOT OPENSSL_INSTALL_DIR)
		message(FATAL_ERROR "Must specify -DOPENSSL_INSTALL_DIR")
	endif()
	set(OPENSSL_BUILD_INSTALL_ROOT ${OPENSSL_INSTALL_DIR})
	set(OPENSSL_PREFIX_OPENSSLDIR ${CMAKE_INSTALL_PREFIX}${OPTEE_ENGINE_INSTALL_DIR}/openssl)
	include(3rd/openssl-cmake/libdefs.cmake)
endif()

get_property(OPENSSL_INSTALL_DIR GLOBAL PROPERTY openssl_build_install_dir_property)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)

# Trusted Application sources
set(TA_DELEGATOR_ROOT ${CMAKE_SOURCE_DIR}/src/ta)

# Build gtest
add_subdirectory(3rd/gtest)

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

if(CLANG)
	set(C_CXX_FLAGS
		"-Wconditional-uninitialized \
		-Wmissing-variable-declarations")
endif()

# Control Debug/Release mode
IF(${CMAKE_BUILD_TYPE} MATCHES "Debug")
	set(C_CXX_FLAGS "${C_CXX_FLAGS} -g3 -O0 -Wno-unused")
else()
	set(C_CXX_FLAGS "${C_CXX_FLAGS} -O3")
endif()

# Add possibility to build Client Application with ASAN
if(ASAN)
	set(CLANG 1)
	set(C_CXX_FLAGS "${C_CXX_FLAGS} -fsanitize=undefined,address,leak -fno-omit-frame-pointer")
	set(LDFLAGS "${LDFLAGS} -fsanitize=undefined,address,leak")
endif()

set(CMAKE_C_FLAGS ${C_CXX_FLAGS})
set(CMAKE_CXX_FLAGS ${C_CXX_FLAGS})
if(CLANG)
	if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
		message(FATAL_ERROR "Clang required for this build")
	endif()

    set(C_CXX_FLAGS "${C_CXX_FLAGS} -Wnewline-eof -fcolor-diagnostics")
endif()

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
    ${CMAKE_DL_LIBS})

IF(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(optee_eng PRIVATE BUILD_DEBUG)
endif()
