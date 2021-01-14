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
	EVP_MD_CTX *       ctx,
	unsigned char *      sig,
	size_t *             sigsz,
	const unsigned char *tb,
	size_t               tbsz);

#endif // BACK_H_
