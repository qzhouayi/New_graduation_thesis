#include "jpake.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <memory.h>

/*
 * In the definition, (xa, xb, xc, xd) are Alice's (x1, x2, x3, x4) or
 * Bob's (x3, x4, x1, x2). If you see what I mean.
 */
    
struct ZHJPAKE_CTX
	{
	BIGNUM *g;
	BIGNUM *h;
	BIGNUM *q;
	BIGNUM *secret;
	BIGNUM *r;
	BIGNUM *key;
	} ;

void ZHJPAKE_Message_init(ZHJPAKE_Message *message)
	{
	message->y = BN_new();
	}
	
void ZHJPAKE_Messge_release(ZHJPAKE_Message *message)
	{
	BN_free(message->y);
	}
	
void ZHJPAKE_Message_generate()
	{
	
	}
    
static void ZHJPAKE_CTX_init(ZHJPAKE_CTX *ctx, const BIGNUM *g,
				const BIGNUM *q, const BIGNUM *h, const BIGNUM *secret)
	{
	ctx->p = BN_dup(p);
	ctx->h = BN_dup(h);
	ctx->q = BN_dup(q);
	ctx->secret = BN_dup(secret);
	ctx->r = BN_new();
	}

static void ZHJPAKE_CTX_release(ZHJPAKE_CTX *ctx)
    {
	BN_clear_free(ctx->g);
	BN_clear_free(ctx->h);
	BN_clear_free(ctx->q);
	BN_clear_free(ctx->secret);
	BN_clear_free(ctx->r);
	
    memset(ctx, '\0', sizeof *ctx);
    }
    
ZHJPAKE_CTX *ZHJPAKE_CTX_new(const BIGNUM *g, const BIGNUM *q, 
			 const BIGNUM *h, const BIGNUM *secret)
    {
    ZHJPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    ZHJPAKE_CTX_init(ctx, g, q, h, secret);

    return ctx;
    }    
   
void ZHJPAKE_CTX_free(ZHJPAKE_CTX *ctx)
    {
    ZHJPAKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

const BIGNUM *ZHJPAKE_get_shared_key(ZHJPAKE_CTX *ctx)
	{
	return ctx->key;
	}
	
