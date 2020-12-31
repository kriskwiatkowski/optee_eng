#include <string.h>
#include <assert.h>

#include <openssl/engine.h>
#include <openssl/evp.h>

#include "back.h"
#include "log.h"
#include "utils.h"

// Extended data index for EC key
static int ec_ex_index = 0;

// OZAPTF: remove
static const EC_POINT *ec_pub_key;
static const BIGNUM *ec_prv_key;

// Context
struct tee_ctx_t {
    // Stores hash of key ID of a key stored in the TEE
    uint8_t key_id[32];
    // OZAPTF: remove
    const BIGNUM *prv;
};

// OZAPTF helper to remove
static int parse_key_from_file(const char *path) {
    int ret = 0;

    BIO *bp;
    EVP_PKEY *key;
    EC_KEY *ec_key;
    const EC_GROUP *group;
    BIGNUM *x, *y;

    bp = BIO_new(BIO_s_file());
    if (!bp) {
        goto end;
    }

    if (!BIO_read_filename(bp, path)) {
        fprintf(stderr, "Failed to open private key file %s", path);
        goto end;
    }

    key = PEM_read_bio_PrivateKey(bp, 0, 0, 0);
    if (!key) {
        goto end;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) goto end;

    // Get curve
    ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!ec_key) goto end;

    ec_pub_key = EC_KEY_get0_public_key(ec_key);
    if (!ec_pub_key) goto end;

    // Get private key
    ec_prv_key = EC_KEY_get0_private_key(ec_key);
    ret = 1;
end:
    BIO_free(bp);
    return ret;
}

int OPTEE_ENG_evp_cb_sign(
    EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *sigsz,
    const unsigned char *tb, size_t tbsz) {
    ENTRY;

    EC_KEY *ec = 0;
    EVP_MD *md = 0;
    EVP_PKEY *pkey = 0;
    const EC_GROUP *group = 0;
    struct tee_ctx_t *op_ctx = 0;
    unsigned int sltmp;
    int ret = 0;

    // OZAPTF: not sure if 64
    static const size_t max_signature_length = 64;

    // if sig not set, return maximum length of the signature buffer
    if (!sig && sigsz) {
        *sigsz = max_signature_length;
        ret = 0;
        goto end;
    }

    if (*sigsz < max_signature_length) {
        /* Signature buffer is to small. The documentation, here:
           https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_sign.html
           doesn't specify what to do in this case. The choices are
           either fail or return truncated signature. I'll just fail
           as truncated ECDSA signature can't be verified. */
        *sigsz = 0;
        goto end;
    }

    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    TEST_NULL(pkey);

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

    if (NID_X9_62_prime256v1 != EC_GROUP_get_curve_name(group)) {
        info("Only p-256 supported");
        ret = -2;
        goto end;
    }

    // Get TEE context as crypto extended data and set it as signing key
    op_ctx = EC_KEY_get_ex_data(ec, ec_ex_index);
    TEST_NULL(op_ctx);
    TEST_OSSL(
        EC_KEY_set_private_key(ec, ec_prv_key),
        INVALID_KEY);

    TEST_OSSL(
        ECDSA_sign(NID_sha256, tb, tbsz, sig, &sltmp, ec),
        CANNOT_SIGN);
    *sigsz = sltmp;

    // That's all, folks!
    ret = 1;
end:
    if (ec) EC_KEY_free(ec);
    return ret;
}

// generate key pair for the ECC key and
static EVP_PKEY* get_ecc_key_pair(
    ENGINE *e,
    struct tee_ctx_t *op,
    int ecc_group_id) {

    EVP_PKEY_CTX *evp_ctx = 0;
    EVP_PKEY *evp_key = 0;
    EC_KEY *ec_key = 0;
    int ret = 0;

    evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, e);
    TEST_NULL(evp_ctx);
    TEST_OSSL(
        EVP_PKEY_paramgen_init(evp_ctx),
        BAD_PARAMETERS);
    // Generate parameters for ECDSA-P256
    TEST_OSSL(
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx, ecc_group_id),
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

    // OZAPTF: set public key received from TEE
    TEST_OSSL(
        EC_KEY_set_public_key(ec_key, ec_pub_key),
        BAD_PARAMETERS);

    // Set handle to private key, stored in the TEE
    EC_KEY_set_ex_data(ec_key, ec_ex_index, op);
    TEST_OSSL(
        EVP_PKEY_set1_engine(evp_key, e),
        INTERNAL);

    ret = 1;
end:
    if (ec_key) {
        // must be "free'd"  as EVP_PKEY_get1 was used
        EC_KEY_free(ec_key);
    }
    if (evp_ctx) {
        EVP_PKEY_CTX_free(evp_ctx);
    }
    if (!ret && evp_key) {
        EVP_PKEY_free(evp_key);
        evp_key = 0;
    }
    return evp_key;
}

EVP_PKEY* OPTEE_ENG_load_private_key(
    ENGINE *e, const char *key_name, UI_METHOD *ui_method,
    void *callback_data) {
    ENTRY;

    NOP(callback_data), NOP(ui_method);

    struct tee_ctx_t *op_ctx = 0;
    EVP_PKEY_CTX *evp_ctx = 0;
    EVP_PKEY *evp_key = 0;
    uint8_t key_digest[32] = {0};
    int ret = 0;

    /* read key from file */
    // OZAPTF
    TEST_OSSL(
        parse_key_from_file(getenv("PRV_KEY")),
        BAD_PARAMETERS);

    // Calculate key-id used internally. It is a sha256
    // caller provided of key name.
    TEST_OSSL(
        EVP_Digest(key_name, strlen(key_name), key_digest, NULL, EVP_sha256(), NULL),
        BAD_PARAMETERS);

    // Create internal TEE context
    op_ctx = malloc(sizeof(*op_ctx));
    TEST_NULL(op_ctx);
    op_ctx->prv = ec_prv_key;
    memcpy(op_ctx->key_id, key_digest, ARRAY_SIZE(op_ctx->key_id));

    // create EVP_PKEY_CTX object for ECDSA-P256 signing
    evp_key = get_ecc_key_pair(e, op_ctx, NID_X9_62_prime256v1);
    TEST_NULL(evp_key);

    if (EVP_PKEY_set1_engine(evp_key, e) != 1) {
        info("Can't set engine for EVP_PKEY");
        EVP_PKEY_free(evp_key);
        evp_key = 0;
    }
    ret = 1;

end:
    if (!ret) {
        if (op_ctx && !evp_key) {
            free(op_ctx);
        }
        if (evp_key) {
            EVP_PKEY_free(evp_key);
        }
    }
    return evp_key;
}
