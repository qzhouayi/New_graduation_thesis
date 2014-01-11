/*
 */

#ifndef HEADER_OMDHKE_H
#define HEADER_OMDHKE_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_OMDHKE
#error OMDHKE is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#include <openssl/bn.h>
#include <openssl/sha.h>

typedef struct OMDHKE_CTX OMDHKE_CTX;

typedef struct 
	{
	BIGNUM *y;
	} OMDHKE_Message;

/* Alloc and release OMDHKE_CTX */	
OMDHKE_CTX *OMDHKE_CTX_new(const BIGNUM *g, const BIGNUM *q, 
			 const BIGNUM *h, const char *password, const char *name, const char *peer_name);
void OMDHKE_CTX_free(OMDHKE_CTX *ctx);
void test_hash();

/* Message generation */
OMDHKE_Message *OMDHKE_Message_new();
void OMDHKE_Message_free(OMDHKE_Message *message);
void OMDHKE_Message_generate(OMDHKE_Message *message, OMDHKE_CTX *ctx);
int OMDHKE_Message_receive(OMDHKE_CTX *ctx, OMDHKE_Message *message);

/* Get shared key of the session */
const BIGNUM *OMDHKE_get_shared_key(OMDHKE_CTX *ctx);

unsigned char dh512_p[]={
		0xBD,0x8B,0xFB,0xC4,0x41,0xF9,0x9F,0x81,0x0E,0x46,0x77,0x1D,
		0x33,0x89,0x2A,0x48,0x9B,0xAA,0x8B,0x8C,0xD9,0xC3,0xB6,0xC0,
		0x11,0x95,0x78,0x18,0x3C,0x50,0x9A,0xEC,0x6D,0x41,0xFF,0x17,
		0x75,0x30,0x08,0xBD,0xCB,0x46,0xB4,0x23,0x5E,0x22,0x9A,0x73,
		0x2B,0x3F,0x5A,0x37,0xC6,0xED,0x7A,0x72,0x60,0x74,0xCA,0x9E,
		0x6A,0x36,0xDC,0x2B,
		};
unsigned char dh512_g[]={
		0x02, 0x04
		};
		
#endif
