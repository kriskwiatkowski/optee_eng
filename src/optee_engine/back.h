#ifndef BACK_H_
#define BACK_H_

#include <stddef.h>
#include <stdint.h>
#include <openssl/ossl_typ.h>

EVP_PKEY* OPTEE_ENG_load_private_key(
    ENGINE *	e,
    const char *key_id,
    UI_METHOD *	ui_method,
    void *		callback_data);

int OPTEE_ENG_evp_cb_sign(
	EVP_PKEY_CTX *      ctx,
	uint8_t *      		sig,
	size_t *            sigsz,
	const uint8_t 		*tb,
	size_t              tbsz);

#endif // BACK_H_
