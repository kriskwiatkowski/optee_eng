#include <stdio.h>
#include <string.h>
#include <user_ta_header_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#ifdef ATTR_REF
#undef ATTR_REF
#endif
#define ATTR_REF(CNT, ATTR, BUF) \
	TEE_InitRefAttribute(&attrs[(CNT)++], (ATTR), (BUF).b, (BUF).sz)

#define LOG_RET(ret) 						\
	if((ret)!=TEE_SUCCESS) { 				\
		EMSG("ERR: %d %X", __LINE__, ret); 	\
		return ret; 						\
	}

// Calculates size of an array
#define ARRAY_SIZE(a) ((sizeof((a))) / sizeof((a)[0]))

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) {
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx) {

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	DMSG("has been called");
	if (param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	EMSG("Session closed\n");
}

// Creates new ECC key
static TEE_ObjectHandle create_ecc_key(struct keypair_t *kp) {
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Attribute attrs[4];
	struct ECC_t *ecc;
	size_t cnt = 0;

 	ecc = &kp->u.ecc;
	res = TEE_AllocateTransientObject(
		TEE_TYPE_ECDSA_KEYPAIR,
		ecc->x.sz * 8,
		&obj);

	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_AllocateTransientObject failed");
		goto err;
	}

	ATTR_REF(cnt, TEE_ATTR_ECC_PRIVATE_VALUE, ecc->scalar);
	ATTR_REF(cnt, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecc->x);
	ATTR_REF(cnt, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecc->y);
	TEE_InitValueAttribute(&attrs[cnt++], TEE_ATTR_ECC_CURVE,ecc->curve_id, 0);
	// TODO: ecc->scalar shouldn't be extractable, but we store it with
	//       the public key, and I need to be able to extract it.
	//       It would be better to store public and private key separately.
	res = TEE_RestrictObjectUsage1(obj, TEE_USAGE_EXTRACTABLE|TEE_USAGE_SIGN);
	if (res != TEE_SUCCESS ) {
		EMSG("E: TEE_RestrictObjectUsage1 failed");
		goto err;
	}

	res = TEE_PopulateTransientObject(obj, attrs, cnt);
	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_PopulateTransientObject failed");
		goto err;
	}
	return obj;

err:
	TEE_FreeTransientObject(obj);
	return TEE_HANDLE_NULL;
}

// Puts the key to the storage
static TEE_Result install_key(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	TEE_ObjectHandle transient_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle persistant_obj = TEE_HANDLE_NULL;
	uint32_t exp_param_types;
	struct keypair_t *kp;
	uint8_t key_id[SHA256_SIZE];

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types ||
		params[1].memref.size != ARRAY_SIZE(key_id)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	kp = (struct keypair_t*)params[0].memref.buffer;
	if (sizeof(*kp) != params[0].memref.size) {
		EMSG("E: wrong size of keypair_t struct");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// Only ECC supported
	if (kp->type != KEYTYPE_ECC) {
		EMSG("E: only ECC keys supported");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	transient_obj = create_ecc_key(kp);
	if (transient_obj == TEE_HANDLE_NULL) {
		EMSG("E: Can't create transient object");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// Input TEE_CreatePersistentObject can't be NWd shared buffer
	memcpy(key_id, params[1].memref.buffer, params[1].memref.size);
	ret = TEE_CreatePersistentObject(
		TEE_STORAGE_PRIVATE,
		key_id, ARRAY_SIZE(key_id),
		TEE_DATA_FLAG_ACCESS_WRITE,
		transient_obj,
		NULL/*data*/, 0 /*data_len*/, &persistant_obj);
	if (ret) {
		EMSG("E: Create");
		return ret;
	}
	IMSG("New key [%02X%02X%02X%02X%02X] registered",
		key_id[0], key_id[1], key_id[2], key_id[3], key_id[4]);
	TEE_FreeTransientObject(transient_obj);
	TEE_CloseObject(persistant_obj);
	return TEE_SUCCESS;
}

// Performs key deletion from the secure storage
static TEE_Result del_key(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	char key_id[SHA256_SIZE] = {0};
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > sizeof(key_id)) {
		EMSG("E: filename too long (>255)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(key_id, params[0].memref.buffer,
		params[0].memref.size);

	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		key_id, params[0].memref.size,
		TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
	if (ret) {
		EMSG("E: Can't open");
		return ret;

	}
	IMSG("Key [%02X%02X%02X%02X%02X] unregistered",
		key_id[0], key_id[1], key_id[2], key_id[3], key_id[4]);
	TEE_CloseAndDeletePersistentObject(obj);
	return TEE_SUCCESS;
}

// returns public key of installed key-pair to the normal world
static TEE_Result get_public_key(uint32_t param_types, TEE_Param params[4]) {
	uint32_t exp_param_types;
	char key_id[SHA256_SIZE] = {0};
	TEE_Result ret;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;

	exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Unexpected params");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < SHA256_SIZE) {
		EMSG("key-id must be SHA256 hash");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(key_id, params[0].memref.buffer, params[0].memref.size);
	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		key_id, ARRAY_SIZE(key_id),
		TEE_DATA_FLAG_ACCESS_READ, &obj);

	if (ret) {
		EMSG("E: Open 0x%X", ret);
		return ret;
	}

	ret = TEE_SUCCESS;
	ret |= TEE_GetObjectBufferAttribute(obj, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		params[1].memref.buffer, &params[1].memref.size);
	ret |= TEE_GetObjectBufferAttribute(obj, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		params[2].memref.buffer, &params[2].memref.size);

	if (ret) {
		EMSG("E: Can't extract public attributes for ECC key");
		goto end;
	}

	IMSG("Public key for ID [%02X%02X%02X%02X%02X] returned",
		key_id[0], key_id[1], key_id[2], key_id[3], key_id[4]);
end:
	TEE_CloseObject(obj);
	return TEE_SUCCESS;
}

// Performs ECDSA signing with a key from secure storage
static TEE_Result sign_ecdsa(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint8_t key_id[SHA256_SIZE];

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE);

	if ((param_types != exp_param_types) ||
		(params[0].memref.size > ARRAY_SIZE(key_id))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// Must be local
	memcpy(key_id, params[0].memref.buffer, params[0].memref.size);

	IMSG("Sign for a key ID [%02X%02X%02X%02X%02X] requested",
		key_id[0], key_id[1], key_id[2], key_id[3], key_id[4]);

	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		key_id, ARRAY_SIZE(key_id),
		TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (ret) {
		EMSG("E: Can't open");
		return ret;
	}

	// perform ECDSA sigining
	ret = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
	LOG_RET(ret);
	ret = TEE_SetOperationKey(op, obj);
	LOG_RET(ret);
	ret = TEE_AsymmetricSignDigest(op, NULL, 0,
		params[1].memref.buffer, params[1].memref.size,
		params[2].memref.buffer, &params[2].memref.size);
	LOG_RET(ret);

	TEE_CloseObject(obj);
	TEE_FreeOperation(op);

	IMSG("Message signed with key ID [%02X%02X%02X%02X%02X]",
		key_id[0], key_id[1], key_id[2], key_id[3], key_id[4]);
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4]) {
	(void)&sess_ctx; /* Unused parameter */
	switch (cmd_id) {
	case TA_INSTALL_KEYS:
		return install_key(param_types, params);
	case TA_DEL_KEYS:
		return del_key(param_types, params);
	case TA_GET_PUB_KEY:
		return get_public_key(param_types, params);
	case TA_SIGN_ECC:
		return sign_ecdsa(param_types, params);
	default:
		EMSG("Request not supported");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
