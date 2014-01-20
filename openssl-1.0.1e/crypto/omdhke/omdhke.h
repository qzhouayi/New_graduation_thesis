/*
 * 
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

/* Data structure of the protocol context */
typedef struct OMDHKE_Client_CTX OMDHKE_Client_CTX;
typedef struct OMDHKE_Server_CTX OMDHKE_Server_CTX;

/* Data structure of the Messages during protocol execution */
typedef struct OMDHKE_Client_Message OMDHKE_Client_Message;
typedef struct OMDHKE_Server_Message OMDHKE_Server_Message;

/* Alloc and release OMDHKE_Client_CTX */	
OMDHKE_Client_CTX *OMDHKE_Client_CTX_new(const char *secret, const char *name);
void OMDHKE_Client_CTX_free(OMDHKE_Client_CTX *ctx);

/* Alloc and release OMDHKE_Server_CTX */	
OMDHKE_Server_CTX *OMDHKE_Server_CTX_new(const char *secret, const char *name);
void OMDHKE_Server_CTX_free(OMDHKE_Server_CTX *ctx);

/* Client Message generation */
OMDHKE_Client_Message *OMDHKE_Client_Message_new();
void OMDHKE_Client_Message_free(OMDHKE_Client_Message *message);
void OMDHKE_Client_Message_generate(OMDHKE_Client_Message *message, OMDHKE_Client_CTX *ctx);

/* Server Message generation */
OMDHKE_Server_Message *OMDHKE_Server_Message_new();
void OMDHKE_Server_Message_free(OMDHKE_Server_Message *message);
void OMDHKE_Server_Message_generate(OMDHKE_Server_Message *message, OMDHKE_Server_CTX *ctx);

/* Message reception */
int OMDHKE_Server_receive(OMDHKE_Server_CTX *ctx, OMDHKE_Client_Message *message);
int OMDHKE_Client_receive(OMDHKE_Client_CTX *ctx, OMDHKE_Server_Message *message);

/* Get shared key of the session */
const BIGNUM *OMDHKE_Client_get_shared_key(OMDHKE_Client_CTX *ctx);
const BIGNUM *OMDHKE_Server_get_shared_key(OMDHKE_Server_CTX *ctx);

#endif
