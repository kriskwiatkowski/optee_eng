#ifndef TA_DELEGATOR_TZ_H
#define TA_DELEGATOR_TZ_H

#include <stdint.h>
#include <stddef.h>

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
	{ 0x00, 0x60, 0x0d, 0xc0, 0xff, 0xee, 0x00, 0x00}}

/*
 * TA properties: multi-instance TA, no specific attribute
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS			TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE			(1 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			(1 * 1024)

/* Extra properties (give a version id and a string name) */
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "TLS signer TZ" },	\
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } \
}

/* The function IDs implemented in this TA */
#define TA_INSTALL_KEYS		0
#define TA_DEL_KEYS         1
#define TA_SIGN_ECC         2
#define TA_GET_PUB_KEY      3

// SHA-256 output size
#define SHA256_SIZE 32

#define MAX_KEY_SIZE 512

struct keybuf_t {
    uint8_t b[MAX_KEY_SIZE];
    size_t sz;
};

typedef enum {
    KEYTYPE_ECC = 1,
    // ... RSA, PQ ...
} keytype_t;

struct keypair_t {
    keytype_t type;
    union {
        struct ECC_t {
            uint32_t curve_id;
            struct keybuf_t scalar;
            struct keybuf_t x;
            struct keybuf_t y;
        } ecc;
        // rsa, pq, ...
    } u;
};

#endif /*TA_DELEGATOR_TZ_H*/
