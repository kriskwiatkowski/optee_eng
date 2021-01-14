#include <stdbool.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include "log.h"
#include "back.h"
#include "utils.h"

#ifdef OPTEE_ENG_ENGINE_ID
#undef OPTEE_ENG_ENGINE_ID
#endif
#define OPTEE_ENG_ENGINE_ID "optee_eng"

#ifdef OPTEE_ENG_ENGINE_NAME
#undef OPTEE_ENG_ENGINE_NAME
#endif
#define OPTEE_ENG_ENGINE_NAME "OpTEE OpenSSL ENGINE (NO TEE VERSION)."

BIO *bio_err = NULL;
static bool is_initialized = false;
static int lib_code = 0;
static int error_loaded = 0;

// Defines error functions implementing OpenSSL API
static ERR_STRING_DATA OPTEE_ENG_err_str_funcs[] = {
#define F(_1, _2) {ERR_PACK(0, GLUE(TEE_F_,_1),0), STR(_2)},
    ERR_F_LIST(F)
#undef F
    {0, NULL}
};

// Defines error reason codes with description strings
static ERR_STRING_DATA OPTEE_ENG_err_str_reasons[] = {
#define F(_1,_2) {ERR_PACK(0, 0, GLUE(TEE_R_,_1)), _2},
    ERR_R_LIST(F)
#undef F
    {0, NULL}
};

// NIDs overriden by the engine
static int reg_nids[1] = {EVP_PKEY_EC};

// Defines library name
static /*const*/ ERR_STRING_DATA OPTEE_ENG_lib_name[] = {
    {0, "OpTEE Engine"},
    {0, NULL}
};

static int OPTEE_ENG_err_strings(void) {
  if (lib_code == 0) {
    lib_code = ERR_get_next_error_library();
  }
  if (!error_loaded) {
#ifndef OPENSSL_NO_ERR
    ERR_load_strings(lib_code, OPTEE_ENG_err_str_funcs);
    ERR_load_strings(lib_code, OPTEE_ENG_err_str_reasons);
    OPTEE_ENG_lib_name->error = ERR_PACK(lib_code, 0, 0);
    ERR_load_strings(0, OPTEE_ENG_lib_name);
#endif
    error_loaded = 1;
  }
  return 1;
}

static void OPTEE_ENG_unload_strings(void) {
  if (error_loaded) {
#ifndef OPENSSL_NO_ERR
    if (!lib_code) {
      crit("Unknown lib_code");
      return;
    }
    ERR_unload_strings(lib_code, OPTEE_ENG_err_str_funcs);
    ERR_unload_strings(lib_code, OPTEE_ENG_err_str_reasons);
    ERR_unload_strings(0, OPTEE_ENG_lib_name);
#endif
    error_loaded = 0;
  }
}

static int OPTEE_ENG_destroy(ENGINE *e) {
    ENTRY;
    NOP(e);

    OPTEE_ENG_unload_strings();
    return 1;
}

static int OPTEE_ENG_pkey_meths(
    ENGINE *          e,
    EVP_PKEY_METHOD **pmeth,
    const int **      nids,
    int               nid) {

    ENTRY;

    if (!pmeth) {
        // Return list of registered NIDs
        debug("Return list of NIDs");
        *nids = reg_nids;
        return 1;
    }

    const EVP_PKEY_METHOD *orig_meth;
    EVP_PKEY_METHOD *new_meth;

    orig_meth = EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (!orig_meth) {
        return 0;
    }

    new_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    EVP_PKEY_meth_copy(new_meth, orig_meth);

    // Bind function pointers of PKEY and ASN1 methods
    EVP_PKEY_meth_set_digestsign(new_meth, OPTEE_ENG_evp_cb_sign);
    *pmeth = new_meth;
    return 1;
}

static int OPTEE_ENG_register_engine(ENGINE *e) {
    ENGINE_set_pkey_meths(e, OPTEE_ENG_pkey_meths);
    return 1;
}

static int OPTEE_ENG_bind(ENGINE *e, const char *id) {
    if (!ERR_load_crypto_strings()) {
        fprintf(stderr, "ERR_load_crypto_strings failed\n");
        return 0;
    }

    /*
    OZAPTF: locks

    if (!OPENSSL_init_crypto(
        OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC, NULL)) {
        fprintf(stderr, "OPENSSL_init_crypto failed\n");
        return 0;
    }
    */

    NOP(id);
    TEST_P(OPTEE_ENG_err_strings());

    /* we set logs here to get potential error traces
     * from library initialization. */
    unsigned level = TEE_DEFAULT_LOG_LEVEL;
    (void)get_env_log_level(&level);
    log_level(level);
    ENTRY;

    // register engine
    TEST_P(ENGINE_set_id(e, OPTEE_ENG_ENGINE_ID));
    TEST_P(ENGINE_set_name(e, OPTEE_ENG_ENGINE_NAME));
    TEST_P(ENGINE_set_destroy_function(e, OPTEE_ENG_destroy));
    TEST_P(ENGINE_set_load_privkey_function(e, OPTEE_ENG_load_private_key));
    TEST_P(OPTEE_ENG_register_engine(e));
    debug("Registration done");

    return 1;
end:
    crit("Method binding failed");
    OPTEE_ENG_unload_strings();
    return 0;
}

IMPLEMENT_DYNAMIC_BIND_FN(OPTEE_ENG_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
