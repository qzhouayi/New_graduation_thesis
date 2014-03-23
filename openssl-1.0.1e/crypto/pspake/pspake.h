/*
 * 
 */

#ifndef HEADER_PSPAKE_H
#define HEADER_PSPAKE_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_PSPAKE
#error PSPAKE is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#include <openssl/bn.h>
#include <openssl/sha.h>

typedef struct PSPAKE_CTX PSPAKE_CTX;

typedef struct PSPAKE_Message PSPAKE_Message;

/* Alloc and release PSPAKE_CTX */	
PSPAKE_CTX *PSPAKE_CTX_new(const char *secret, const char *name, const char *peer_name);
void PSPAKE_CTX_free(PSPAKE_CTX *ctx);

// obsoleted
/* Helper function */
//~ void test_hash();
//~ void print_bn(const char *name, const BIGNUM *bn);

/* Message generation */
PSPAKE_Message *PSPAKE_Message_new();
void PSPAKE_Message_free(PSPAKE_Message *message);
void PSPAKE_Message_generate(PSPAKE_Message *message, PSPAKE_CTX *ctx);
int PSPAKE_Message_receive(PSPAKE_CTX *ctx, PSPAKE_Message *message);

/* Get shared key of the session */
const BIGNUM *PSPAKE_get_shared_key(PSPAKE_CTX *ctx);

/* print the parameters of ctx */
void print_ctx(const PSPAKE_CTX *ctx);

#endif
