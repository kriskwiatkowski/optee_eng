cmake_minimum_required(VERSION 3.13)
include(ExternalProject)
find_program(MAKE_PROGRAM make)

# The Configure script will set the CFLAGS
set(CMAKE_C_FLAGS "")
set(OPENSSL_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build)
# Indicates where OpenSSL is placed after build. That path is used in
# PQSDK build, but that's not the same as installing a package.
set(OPENSSL_BUILD_INSTALL_ROOT ${CMAKE_CURRENT_BINARY_DIR}/openssl-install)
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_BUILD_INSTALL_ROOT}/include)
# OpenSSL is compiled with -prefix and --openssldir set to ${OPENSSL_PREFIX_OPENSSLDIR},
# without RPATH. When used for PQS Engine testing it is placed in :
#   ${OPENSSL_BUILD_INSTALL_ROOT}/${OPENSSL_PREFIX_OPENSSLDIR}
# But when installing it is placed in
#   ${OPENSSL_PREFIX_OPENSSLDIR}
set(OPENSSL_PREFIX_OPENSSLDIR ${CMAKE_INSTALL_PREFIX}${PQSDK_INSTALL_DIR}/openssl)
include(libdefs.cmake)

message("OpenSSL root dir: ${OPENSSL_ROOT_DIR}")
message("OpenSSL install dir: ${OPENSSL_BUILD_INSTALL_ROOT}")
message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL crypto lib: ${OPENSSL_LIB_CRYPTO}")
message("OpenSSL ssl lib: ${OPENSSL_LIB_SSL}")
# TODO: add  no-deprecated. Need to get rid of ERR_load_crypto_strings and OBJ_cleanup first
set(OPENSSL_CONFIG_ARGS no-shared shared threads)

if(DEBUG)
    set(OPENSSL_CONFIG_ARGS ${OPENSSL_CONFIG_ARGS} -d -g3 -O0 no-asm  -fno-omit-frame-pointer -fno-inline-functions)
elseif(OQS_SPEED_COMPARE AND OQS_GENERIC)
    set(OPENSSL_CONFIG_ARGS ${OPENSSL_CONFIG_ARGS} no-asm)
endif()

# Define dependencies on libcrypto.so and libssl.so
add_dependencies(
    OpenSSL_crypto_shared
    OpenSSL)
add_dependencies(
    OpenSSL_ssl_shared
    OpenSSL)

# Add OpenSSL as external project
ExternalProject_Add(OpenSSL
    SOURCE_DIR ${OPENSSL_ROOT_DIR}
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-build
    CONFIGURE_COMMAND <SOURCE_DIR>/config -debug ${OPENSSL_CONFIG_ARGS} --prefix=${OPENSSL_PREFIX_OPENSSLDIR} --openssldir=${OPENSSL_PREFIX_OPENSSLDIR} --strict-warnings
    BUILD_COMMAND ${MAKE_PROGRAM} CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER} LD=${CMAKE_LINKER}
    INSTALL_DIR /
    INSTALL_COMMAND make DESTDIR=${OPENSSL_BUILD_INSTALL_ROOT} install
)

install(DIRECTORY ${OPENSSL_BUILD_INSTALL_ROOT}/${OPENSSL_PREFIX_OPENSSLDIR}/.. DESTINATION ${OPENSSL_PREFIX_OPENSSLDIR})
install(DIRECTORY ${OPENSSL_BUILD_INSTALL_ROOT}${OPENSSL_PREFIX_OPENSSLDIR}/bin/ DESTINATION
    ${OPENSSL_PREFIX_OPENSSLDIR}/bin
    FILE_PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)
set_property(GLOBAL PROPERTY openssl_build_dir_property ${OPENSSL_BUILD_DIR})
