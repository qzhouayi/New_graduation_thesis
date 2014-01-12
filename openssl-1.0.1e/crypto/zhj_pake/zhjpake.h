/*
 * 
 */

#ifndef HEADER_ZHJPAKE_H
#define HEADER_ZHJPAKE_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_ZHJPAKE
#error ZHJPAKE is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#include <openssl/bn.h>
#include <openssl/sha.h>

typedef struct 
	{
	BIGNUM *g;
	BIGNUM *h;
	BIGNUM *q;
	BIGNUM *secret;
	BIGNUM *r;
	BIGNUM *key;
	BN_CTX *ctx;
	BIGNUM *y;
	BIGNUM *y_;
	char *peer_name;
	char *name;
	} ZHJPAKE_CTX;
	
typedef struct 
	{
	BIGNUM *y;
	} ZHJPAKE_Message;

/* Alloc and release ZHJPAKE_CTX */	
ZHJPAKE_CTX *ZHJPAKE_CTX_new(const char *secret, const char *name, const char *peer_name);
void ZHJPAKE_CTX_free(ZHJPAKE_CTX *ctx);

/* Helper function */
void test_hash();
void print_bn(const char *name, const BIGNUM *bn);

/* Message generation */
ZHJPAKE_Message *ZHJPAKE_Message_new();
void ZHJPAKE_Message_free(ZHJPAKE_Message *message);
void ZHJPAKE_Message_generate(ZHJPAKE_Message *message, ZHJPAKE_CTX *ctx);
int ZHJPAKE_Message_receive(ZHJPAKE_CTX *ctx, ZHJPAKE_Message *message);

/* Get shared key of the session */
const BIGNUM *ZHJPAKE_get_shared_key(ZHJPAKE_CTX *ctx);

#endif
