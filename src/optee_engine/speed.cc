#include <stdint.h>
#include <vector>

#include <gtest/gtest.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include <benchmark/benchmark.h>

// Size of the input message. It doesn't matter
// for speed as hashing is done in the REE anyway
#define MSG_SIZE 32

// Name of the key stored in the TEE
#define KEY_NAME "bench_key"

// Path to the engine library
#define OPTEE_ENG_PATH "/opt/liboptee_eng.so"

// Engine ID
#define OPTEE_ID "optee"

static void SignREE(benchmark::State& state) {

    unsigned char msg[MSG_SIZE];
    EVP_MD_CTX *  mctx = EVP_MD_CTX_new();
    EVP_PKEY *    pkey = NULL, *params = NULL;
    EVP_PKEY_CTX *pctx, *kctx;

    ASSERT_TRUE(mctx);

    // Initialize parameters for NIST P-256 curve
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
    ASSERT_TRUE(pctx);
    ASSERT_TRUE(EVP_PKEY_paramgen_init(pctx));
    ASSERT_TRUE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1));
    ASSERT_TRUE(EVP_PKEY_paramgen(pctx, &params));
    kctx = EVP_PKEY_CTX_new(params, NULL);
    ASSERT_TRUE(kctx);

    // Generate key with paramters stored in kctx
    ASSERT_EQ(EVP_PKEY_keygen_init(kctx), 1);
    ASSERT_EQ(EVP_PKEY_keygen(kctx, &pkey), 1);
    ASSERT_TRUE(pkey);

    // Setup buffer for signature
    size_t siglen = EVP_PKEY_size(pkey);
    std::vector<uint8_t> sig;
    sig.reserve(siglen);

    // Perform benchmarking for signing
	ASSERT_EQ(EVP_DigestSignInit(mctx, NULL, 0, 0, pkey), 1);
	for (auto _ : state) {
        ASSERT_EQ(EVP_DigestSign(mctx, sig.data(), &siglen, msg, MSG_SIZE), 1);
        siglen = EVP_PKEY_size(pkey);
	}
	EVP_MD_CTX_free(mctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
}

static void SignTEE(benchmark::State& state) {
    const char key_name[] = "bench_key\0";
	// load engine
    unsigned char msg[MSG_SIZE];
    EVP_PKEY *    pkey = NULL;
    EVP_MD_CTX *  mctx = EVP_MD_CTX_new();
    ENGINE *e = NULL;

    ENGINE_load_dynamic();
    e = ENGINE_by_id("dynamic");
    ASSERT_TRUE(e);

    ENGINE_ctrl_cmd_string(e, "SO_PATH", OPTEE_ENG_PATH, 0);
    ENGINE_ctrl_cmd_string(e, "ID", OPTEE_ID, 0);
    ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
    ENGINE_set_default(e, ENGINE_METHOD_ALL);
    ERR_clear_error();

    pkey = ENGINE_load_private_key(e, key_name, 0, 0);
    ASSERT_TRUE(pkey);

    size_t siglen = EVP_PKEY_size(pkey);
    std::vector<uint8_t> sig;
    sig.reserve(siglen);

	ASSERT_EQ(EVP_DigestSignInit(mctx, NULL, 0, 0, pkey), 1);
	for (auto _ : state) {
		EVP_DigestSign(mctx, sig.data(), &siglen, msg, sizeof msg);
		siglen = EVP_PKEY_size(pkey);
	}
	EVP_MD_CTX_free(mctx);
	EVP_PKEY_free(pkey);
}

BENCHMARK(SignREE);
BENCHMARK(SignTEE);
BENCHMARK_MAIN();
