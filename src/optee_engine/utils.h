#ifndef UTILS_H_
#define UTILS_H_

// Concatenate a and b
#define GLUE(a, b) GLUE_(a, b)
#define GLUE_(a, b) a##b

// Stringify constants
#define STR(x) STR_(x)
#define STR_(x) #x

// Calculates size of an array
#define ARRAY_SIZE(a) ((sizeof((a))) / sizeof((a)[0]))

// In case exp is not set, it produces error trace and goes to 'end'
#define TEST_OSSL(exp, result)                          \
    do {                                                \
        if (!(exp)) {                                   \
            crit("Expression failed [%d: %s]: \"%s\"\n",\
                  GLUE(TEE_R_, result),                 \
                  STR(GLUE(TEE_R_, result)),            \
                  #exp);                                \
            goto end;                                   \
        }                                               \
    } while (0)

/* In case result of the operation is not TEE_R_SUCCESS, it
 * produces error trace and jumps to the 'end' */
#define CHECK__(result, OK_CODE)                       \
    do {                                               \
        if ((result) != OK_CODE) {                     \
            crit("Expression failed: %s\n", #result);  \
            goto end;                                  \
        }                                              \
    } while (0)

// In case exp is NULL, it produces error trace and goes to 'end'
#define TEST_NULL(exp)                     \
    do {                                       \
        if (!(exp)) {                          \
            crit("NULL pointer: %s\n", #exp);  \
            goto end;                          \
        }                                      \
    } while (0)

// Check if call to GP API returns success
#define TEST_GP(exp) CHECK__(exp, TEEC_SUCCESS)
// Check if call to OpenSSL's API returns success
#define TEST_P(exp) CHECK__(exp, 1)

// ID's of the PKEY_* functions implementing OpenSSL API
#define ERR_F_LIST(_)                                   \
    _(SIGN, OPTEE_ENG_evp_cb_sign)                      \
    _(LOAD_PRV_KEY, OPTEE_ENG_load_private_key)

enum {
    TEE_F_NONE = 100,
#define DEF_ERR_F_LIST(_1, _2) TEE_F_##_1,
    ERR_F_LIST(DEF_ERR_F_LIST)
#undef DEF_ERR_F_LIST
};

#define ERR_R_LIST(_)                                            \
    _(SUCCESS, "Success")                                        \
    _(GENERIC, "Generic")                                        \
    _(CANNOT_ALLOCATE_KEY, "key allocation")                     \
    _(BAD_SIGNATURE, "bad signature")                            \
    _(CANNOT_SIGN, "signing operation failed")                   \
    _(CANNOT_GEN_KEY, "failed to generate keys")                 \
    _(INVALID_ENCODING, "invalid encoding")                      \
    _(INVALID_KEY, "invalid key")                                \
    _(INVALID_PEER_KEY, "invalid peer key")                      \
    _(WRONG_PRVKEY_BUF, "invalid private key")                   \
    _(WRONG_PUBKEY_BUF, "invalid public key")                    \
    _(KEYS_NOT_SET, "keys not set")                              \
    _(MISSING_NID_DATA, "failed to get nid_data struct pointer") \
    _(MISSING_PRIVATE_KEY, "missing private key")                \
    _(RNG_FAILED, "random number generation failed")             \
    _(BAD_PARAMETERS, "bad parameters found")                    \
    _(PASSED_NULL_PARAMETER, "null pointer provided")            \
    _(NOT_SUPPORTED, "not supported")                            \
    _(WRONG_LENGTH, "wrong length")                              \
    _(OUT_OF_MEMORY, "not enough memory")                        \
    _(INTERNAL, "internal error")                                \
    _(VALUE_NOT_SET, "value not set")

enum {
    TEE_R_NONE = 100,
#define DEF_ERR_R_LIST(_1, _2) TEE_R_##_1,
    ERR_R_LIST(DEF_ERR_R_LIST)
#undef DEF_ERR_R_LIST
};

#endif // UTILS_H_
