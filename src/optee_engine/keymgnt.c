/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdbool.h>

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <user_ta_header_defines.h>

#define TEE_ECC_CURVE_NIST_P256 0x00000003

static uint32_t curve_openssl_to_tee(int openssl_id) {
    if (openssl_id != NID_X9_62_prime256v1) {
        return 0;
    }
    return TEE_ECC_CURVE_NIST_P256;
}

// kp_bncpy():
// * buf : either destination buffer or NULL. If NULL buffer is initialized
static void kp_bncpy(struct keybuf_t *b, const BIGNUM *bn) {
    b->sz = BN_num_bytes(bn);
    // Ensure field is not empty
    assert(b->sz);
    // Ensure allocation hasn't failed
    (void)BN_bn2bin(bn, &b->b[0]);
}

static bool get_keypair(EVP_PKEY *key, struct keypair_t *keypair) {
    switch (EVP_PKEY_type(EVP_PKEY_id(key))) {
    case EVP_PKEY_EC: {
        EC_KEY *ec_key;
        const EC_POINT *ec_pub_key;
        const EC_GROUP *group;
        BIGNUM *x, *y;

        keypair->type = KEYTYPE_ECC;
        BN_CTX *ctx = BN_CTX_new();
        if (!ctx) return false;

        // Get curve
        ec_key = EVP_PKEY_get1_EC_KEY(key);
        if (!ec_key) return false;

        ec_pub_key = EC_KEY_get0_public_key(ec_key);
        if (!ec_pub_key) return false;

        group = EC_KEY_get0_group(ec_key);
        if (!group) return false;

        // Get private key
        const BIGNUM *bn = EC_KEY_get0_private_key(ec_key);
        kp_bncpy(&keypair->u.ecc.scalar, bn);

        // Get public key
        keypair->u.ecc.curve_id
            = curve_openssl_to_tee(EC_GROUP_get_curve_name(group));

        x = BN_new(); y = BN_new();
        if (!x || !y) return false;

        if (!EC_POINT_get_affine_coordinates_GFp(group, ec_pub_key, x, y, ctx)) {
            BN_free(x); BN_free(y);
            return false;
        }

        kp_bncpy(&keypair->u.ecc.x, x);
        kp_bncpy(&keypair->u.ecc.y, y);
        OPENSSL_free(ctx);
        BN_free(x); BN_free(y); // OMG, refactoring is necessairy

        break;
    }
    default:
        errx(1, "Unsupported key type");
        return false;
    }

    return true;
}

// parse_key_from_file: adds a private key from a file location
static int parse_key_from_file(
    const char *path,
    struct keypair_t *kp) {

    BIO *bp;
    EVP_PKEY *key;
    int ret = 0;

    bp = BIO_new(BIO_s_file());
    if (!bp) {
        goto end;
    }

    if (!BIO_read_filename(bp, path)) {
        errx(1, "Failed to open private key file %s", path);
        goto end;
    }

    key = PEM_read_bio_PrivateKey(bp, 0, 0, 0);
    if (!key) {
        errx(1, "PEM_read_bio_PrivateKey: failed");
        goto end;
    }

    if (!get_keypair(key, kp)) {
        errx(1, "get_keypair: failed");
        goto end;
    }

    ret = 1;
end:
    BIO_free(bp);
    return ret;
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
    uint32_t cmd;
    struct keypair_t kp = {0};
    uint32_t err_origin;
    uint8_t key_id[32];

	// Initialize a context connecting us to the TEE
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	// Open a session to the TA identified by uuid
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * TA_INSTALL_KEYS is the actual function in the TA to be
	 * called.
	 */
    if (argc < 2) {
        errx(1, "Key name not provided");
    }

    if (!EVP_Digest(argv[2], strlen(argv[2]), key_id, NULL, EVP_sha256(), NULL)) {
        errx(1, "EVP_Digest");
    }

    if (!strncmp(argv[1], "put", 3)) {
        cmd = TA_INSTALL_KEYS;
        if (argc < 3) {
            errx(1, "Filename missing\n");
        }

        if (!parse_key_from_file(argv[3], &kp)) {
            errx(1, "parse_key_from_file() failed");
        }

        op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_NONE,
                        TEEC_NONE);
        op.params[0].tmpref.buffer = (void*) &kp;
        op.params[0].tmpref.size = sizeof(kp);
        op.params[1].tmpref.buffer = key_id;
        op.params[1].tmpref.size = 32;
    } else if (!strncmp(argv[1], "del", 3)) {
        cmd = TA_DEL_KEYS;
        op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_NONE,
                        TEEC_NONE,
                        TEEC_NONE);
        op.params[0].tmpref.buffer = key_id;
        op.params[0].tmpref.size = 32;
    } else {
        errx(1, "E: Command must be 'put <key_name> filename' or 'del <key_name>'");
    }

	res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
            res, err_origin);
    }

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
