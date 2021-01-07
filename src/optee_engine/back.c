#include <string.h>
#include <assert.h>
#include <err.h>

// OpenSSL
#include <openssl/engine.h>
#include <openssl/evp.h>

// OpTEE
#include <tee_client_api.h>
#include <user_ta_header_defines.h>

#include "back.h"
#include "log.h"
#include "utils.h"

// Only ECDSA/p256 scheme is supported
#define CURVE_ID NID_X9_62_prime256v1
// Coordinate byte size in the NIST-P256
#define ECC_POINT_BSZ 32

// Extended data index for EC key
static int ec_ex_index = 0;

struct session_t {
    // TEE session context
    TEEC_Context ctx;
    // Handle to the TEE session
    TEEC_Session tee_sess;
    // SHA-256 hash of a key ID, used for key indexing inside TEE
    uint8_t key_id[SHA256_SIZE];
};

// Creates session with the TEE. On success, sets the sess and returns
// true, otherwise false.
static bool create_tee_session(struct session_t *sess) {
    TEEC_Result res;
    uint32_t err_origin;
    TEEC_UUID uuid = TA_UUID;

    // Initialize a context connecting us to the TEE
    res = TEEC_InitializeContext(NULL, &sess->ctx);
    if (res != TEEC_SUCCESS) {
        info("TEEC_InitializeContext failed with code 0x%x", res);
        goto end;
    }

    // Open a session with TEE
    res = TEEC_OpenSession(&sess->ctx, &sess->tee_sess, &uuid,
                   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        info("TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);
        goto end;
    }

end:
    return res == TEEC_SUCCESS;
}

// Creates session with the TEE. Returns true on success, otherwise false.
static void close_tee_session(struct session_t *sess) {
    if(!sess) {
        return;
    }
    TEEC_CloseSession(&sess->tee_sess);
    TEEC_FinalizeContext(&sess->ctx);
}

// Load public key. This implementation loads it from TEE
static const EC_POINT* get_public_ec_point_from_tee(
    struct session_t *sess) {
    ENTRY;

    const EC_POINT *ec_pub_key = 0;
    uint8_t coord_x[ECC_POINT_BSZ] = {0};
    uint8_t coord_y[ECC_POINT_BSZ] = {0};
    BIGNUM *x_bn = 0, *y_bn = 0;
    EC_POINT *point = 0;
    EC_GROUP *group = 0;
    EC_KEY *ec_key = 0;
    BN_CTX *ctx = 0;
    int res;
    uint32_t err_origin;
    TEEC_Operation op;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_MEMREF_TEMP_INOUT,
                    TEEC_MEMREF_TEMP_INOUT,
                    TEEC_NONE);
    op.params[0].tmpref.buffer = sess->key_id;
    op.params[0].tmpref.size = ARRAY_SIZE(sess->key_id);
    op.params[1].tmpref.buffer = coord_x;
    op.params[1].tmpref.size = ECC_POINT_BSZ;
    op.params[2].tmpref.buffer = coord_y;
    op.params[2].tmpref.size = ECC_POINT_BSZ;
    if (!create_tee_session(sess)) {
        crit("TEE session: can't create");
        return 0;
    }
    res = TEEC_InvokeCommand(&sess->tee_sess, TA_GET_PUB_KEY, &op, &err_origin);
    close_tee_session(sess);

    if (res != TEEC_SUCCESS) {
        crit("TEE session: TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
        return 0;
    }

    if ((op.params[1].tmpref.size != ECC_POINT_BSZ) ||
        (op.params[2].tmpref.size != ECC_POINT_BSZ)) {
        crit("Wrong length of public key received");
        return 0;
    }

    // Convert received affine coordinate into EC public key
    ctx = BN_CTX_new();
    group = EC_GROUP_new_by_curve_name(CURVE_ID);
    point = EC_POINT_new(group);
    ec_key = EC_KEY_new();

    TEST_NULL(ctx);
    TEST_NULL(group);
    TEST_NULL(point);
    TEST_NULL(ec_key);

    x_bn = BN_bin2bn(op.params[1].tmpref.buffer,
        op.params[1].tmpref.size, x_bn);
    y_bn = BN_bin2bn(op.params[2].tmpref.buffer,
        op.params[2].tmpref.size, y_bn);
    if (!x_bn||!y_bn) {
        crit("Can't convert octet strings to BN");
        goto end;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(group, point, x_bn, y_bn, ctx)) {
        crit("Can't convert BN to point");
        goto end;
    }

    if (!EC_KEY_set_group(ec_key, group) ||
        !EC_KEY_set_public_key(ec_key, point)) {
        crit("Can't set public key");
        goto end;
    }

    ec_pub_key = EC_KEY_get0_public_key(ec_key);

end:
    BN_free(x_bn);
    BN_free(y_bn);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return ec_pub_key;
}

// Construct EVP_PKEY with private key stored in the TEE
static EVP_PKEY* load_key_pair_ec(
    struct session_t *sess,
    ENGINE *e) {

    ENTRY;

    const EC_POINT *ec_pub_key = 0;
    EVP_PKEY_CTX *evp_ctx = 0;
    EVP_PKEY *evp_key = 0;
    EC_KEY *ec_key = 0;
    uint8_t *hash_key_id = 0;
    int ret = 0;

    // Generate parameters for ECDSA-P256
    evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e);
    TEST_NULL(evp_ctx);
    TEST_OSSL(
        EVP_PKEY_paramgen_init(evp_ctx),
        BAD_PARAMETERS);
    TEST_OSSL(
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, CURVE_ID),
        BAD_PARAMETERS);
    TEST_OSSL(
        EVP_PKEY_paramgen(evp_ctx, &evp_key),
        BAD_PARAMETERS);
    TEST_NULL(evp_key);

    // Get pointer to EC key
    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);

    /* OpenSSL assumes that the private key also contains corresponding
     * public key. That's because after loading the server/client
     * certificate OpenSSL performs some checks. One of those checks
     * is to compare public key from the certificate to the public
     * key from the private key (evp_key here). Obviously, this check
     * fails if public key is not set, which then causes failure when
     * starting TLS server.
     * There are at least 2 solutions for that - either
     * override method for comparing the key (PKEY_ASN1_METHOD)
     * and implement those checks in more "TEE friendly" way. Or, store
     * private and public key in the TEE and return public key to
     * Normal World, on Client Application request. Second option is
     * implemented here, as that's easier.
     */
    ec_pub_key = get_public_ec_point_from_tee(sess);
    TEST_NULL(ec_pub_key);
    TEST_OSSL(
        EC_KEY_set_public_key(ec_key, ec_pub_key),
        BAD_PARAMETERS);

    // Set ID of a private key, stored in the TEE
    hash_key_id = (void*)malloc(SHA256_SIZE);
    TEST_NULL(hash_key_id);
    memcpy(hash_key_id, sess->key_id, SHA256_SIZE);
    EC_KEY_set_ex_data(ec_key, ec_ex_index, hash_key_id);
    TEST_OSSL(
        EVP_PKEY_set1_engine(evp_key, e),
        INTERNAL);

    ret = 1;
end:
    EC_KEY_free(ec_key);
    EVP_PKEY_CTX_free(evp_ctx);
    if (!ret && evp_key) {
        EVP_PKEY_free(evp_key);
        evp_key = 0;
    }
    return evp_key;
}

// ENGINE_set_load_privkey_function callback. Retrieves public key
// from TEE and sets a handler for the private key stored in the TEE.
EVP_PKEY* OPTEE_ENG_load_private_key(
    ENGINE *e, const char *key_name, UI_METHOD *ui_method,
    void *callback_data) {
    NOP(callback_data), NOP(ui_method);

    ENTRY;

    EVP_PKEY *evp_key = 0;
    struct session_t sess;
    int ret = 0;

    // Calculate key-id used internally. It is a sha256
    // caller provided of key name.
    TEST_OSSL(
        EVP_Digest(key_name,
            strlen(key_name), sess.key_id, NULL, EVP_sha256(), NULL),
        BAD_PARAMETERS);

    // Create EVP_PKEY object. Currently only ECDSA/p256 is supported.
    // Normally it would be a switch-case for all supported methods.
    evp_key = load_key_pair_ec(&sess, e);
    TEST_NULL(evp_key);

    // Some calls related to EVP_PKEY must be forwaded to
    // OpTEE engine.
    if (EVP_PKEY_set1_engine(evp_key, e) != 1) {
        info("Can't set engine for EVP_PKEY");
        EVP_PKEY_free(evp_key);
        evp_key = 0;
    }
    ret = 1;

end:
    if (!ret) {
        EVP_PKEY_free(evp_key);
    }
    return evp_key;
}

int OPTEE_ENG_evp_cb_sign(
    EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *sigsz,
    const uint8_t *tb, size_t tbsz) {
    ENTRY;

    const EC_GROUP *group = 0;
    EVP_PKEY *pkey = 0;
    EC_KEY *ec = 0;
    EVP_MD *md = 0;
    ECDSA_SIG *sig_ob = 0;
    BIGNUM *r = 0, *s = 0;
    TEEC_Operation op;

    uint8_t *hash_key_id = 0;
    int ret = 0;
    uint32_t err_origin;
    struct session_t sess = {0};
    uint8_t sign[64] = {0};

    TEST_NULL(sigsz);

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    TEST_NULL(pkey);

    // Check if ECDSA/p256-SHA256 signature was requested
    if (EVP_PKEY_type(EVP_PKEY_id(pkey)) != EVP_PKEY_EC) {
        info("Only ECDSA supported for signing");
        ret = -2;  // doc says to set -2 in this case
        goto end;
    }

    if (!EVP_PKEY_CTX_get_signature_md(ctx, &md) ||
        (md != EVP_sha256())) {
        // We only support ECDSA+P-256+SHA256
        info("Only SHA256 supported for signing");
        ret = -2;
        goto end;
    }

    ec = EVP_PKEY_get1_EC_KEY(pkey);
    TEST_NULL(ec);
    group = EC_KEY_get0_group(ec);
    TEST_NULL(group);
    if (CURVE_ID != EC_GROUP_get_curve_name(group)) {
        info("Only NIST P-256 supported");
        ret = -2;
        goto end;
    }

    // Request message singing from TEE
    memset(&op, 0, sizeof(op));
    hash_key_id = EC_KEY_get_ex_data(ec, ec_ex_index);
    TEST_NULL(hash_key_id);
    op.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_MEMREF_TEMP_INOUT,
                    TEEC_NONE);
    op.params[0].tmpref.buffer = hash_key_id;
    op.params[0].tmpref.size = SHA256_SIZE;
    op.params[1].tmpref.buffer = (uint8_t*)tb;
    op.params[1].tmpref.size = tbsz;
    op.params[2].tmpref.buffer = sign;
    op.params[2].tmpref.size = ARRAY_SIZE(sign);
    if (!create_tee_session(&sess)) {
        info("TEE session: can't create");
        goto end;
    }
    ret = TEEC_InvokeCommand(&sess.tee_sess, TA_SIGN_ECC, &op, &err_origin);
    close_tee_session(&sess);
    if (ret != TEEC_SUCCESS) {
        info("TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            ret, err_origin);
        goto end;
    }

    // Convert raw ECDSA signature (r,s) into DER encoded signature.
    const size_t h = ARRAY_SIZE(sign)/2;
    r = BN_bin2bn(sign+0, h, r);
    s = BN_bin2bn(sign+h, h, s);
    if (!r||!s) {
        info("Can't create r&s of ECDSA SIGN");
        goto end;
    }
    sig_ob = ECDSA_SIG_new();
    // r,s are not NULL, so this call never fails
    (void)ECDSA_SIG_set0(sig_ob, r, s);

    // if sig not set, return maximum length of the signature buffer
    if (!sig && sigsz) {
        *sigsz = i2d_ECDSA_SIG(sig_ob, 0);
        goto end;
    }

    if (*sigsz < i2d_ECDSA_SIG(sig_ob, 0)) {
        /* Signature buffer is to small. The documentation, here:
           https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_sign.html
           doesn't specify what to do in this case. The choices are
           either fail or return truncated signature. I'll just fail
           as truncated ECDSA signature can't be verified. */
        goto end;
    }

    *sigsz = i2d_ECDSA_SIG(sig_ob, &sig);
    if (!*sigsz) {
        info("Can't DER encode signature");
        goto end;
    }

    // That's all, folks!
    ret = 1;
end:
    if (ec) EC_KEY_free(ec);
    if (!sig_ob) {
        // Calling ECDSA_SIG_set0 transfers the ownership of
        // r,s to the ECDSA_SIG object. The ECDSA_SIG_free
        // takes care of freeing it.
        ECDSA_SIG_free(sig_ob);
    } else {
        BN_free(r);
        BN_free(s);
    }
    return ret;
}
