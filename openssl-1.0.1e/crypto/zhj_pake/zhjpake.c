#include "zhjpake.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <memory.h>
#include <stdio.h>
/*
 * ZHJPAKE
 */
    
struct ZHJPAKE_CTX
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
	} ;

/* given the password(string), use SHA1 to hash it and return the result mod q */
static void hashpassword(BIGNUM *hash_result, const char *password, BN_CTX *ctx, const BIGNUM *q)
	{
	SHA_CTX sha;
	size_t length = strlen(password);
	BIGNUM *hash_bn = BN_new();
	unsigned char digest[SHA_DIGEST_LENGTH];
	
	SHA1_Init(&sha);
    SHA1_Update(&sha, password, length);
    SHA1_Final(digest, &sha);
    BN_bin2bn(digest, SHA_DIGEST_LENGTH, hash_bn);
    
	BN_mod(hash_result, hash_bn, q, ctx);
	}
	
static void ZHJPAKE_Message_init(ZHJPAKE_Message *message)
	{
	message->y = BN_new();
	}
	
static void ZHJPAKE_Message_release(ZHJPAKE_Message *message)
	{
	BN_free(message->y);
	}
	
void ZHJPAKE_Message_generate(ZHJPAKE_Message *message, ZHJPAKE_CTX *ctx)
	{
	BIGNUM *t1 = BN_new();
	BIGNUM *t2 = BN_new();
	
	/* just for debugging */
	static int cnt = 0;
	cnt++;
	
	/* r belongs to [0, q) */
	BN_rand_range(ctx->r, ctx->q);
	
	/* t1 = g^r mod q */
	BN_mod_exp(t1, ctx->g, ctx->r, ctx->q, ctx->ctx);
		
	/* t2 = h^secret mod q */
	BN_mod_exp(t2, ctx->h, ctx->secret, ctx->q, ctx->ctx);
		
	/* ctx->y = t1 * t2 mod q */
	BN_mod_mul(ctx->y, t1, t2, ctx->q, ctx->ctx);
		
	/* message->y = ctx->y */
	message->y = BN_dup(ctx->y);
	
	/* print the random number r generated (just for debugging) */
	if (cnt == 1)
	{
	print_bn("alice's r", ctx->r);
	}
	else
	{
	print_bn("bob's r", ctx->r);
	}
	}

ZHJPAKE_Message *ZHJPAKE_Message_new()
	{
	ZHJPAKE_Message *message = OPENSSL_malloc(sizeof *message);

    ZHJPAKE_Message_init(message);

    return message;
	}

void ZHJPAKE_Message_free(ZHJPAKE_Message *message)
	{
	ZHJPAKE_Message_release(message);
    OPENSSL_free(message);
	}
	    
int ZHJPAKE_Message_receive(ZHJPAKE_CTX *ctx, ZHJPAKE_Message *message)
	{
		ctx->y_ = BN_dup(message->y);
		return 0;
	}
	
static void ZHJPAKE_CTX_init(ZHJPAKE_CTX *ctx, const BIGNUM *g, const BIGNUM *q, 
		const BIGNUM *h, const char *password, const char *name, const char *peer_name)
	{
	ctx->g = BN_dup(g);
	ctx->h = BN_dup(h);
	ctx->q = BN_dup(q);
	ctx->ctx = BN_CTX_new();
	ctx->r = BN_new();
	ctx->y = BN_new();
	ctx->key = NULL;
	ctx->y_ = NULL;
	
	ctx->name = OPENSSL_strdup(name);
	ctx->peer_name = OPENSSL_strdup(peer_name);
	
	/* hash the given string password to get a Big Number ctx->secret */
	ctx->secret = BN_new();
	hashpassword(ctx->secret, password, ctx->ctx, q);
	}

static void ZHJPAKE_CTX_release(ZHJPAKE_CTX *ctx)
    {
	BN_clear_free(ctx->g);
	BN_clear_free(ctx->h);
	BN_clear_free(ctx->q);
	BN_clear_free(ctx->secret);
	BN_clear_free(ctx->r);
	BN_clear_free(ctx->y);
	BN_clear_free(ctx->y_);
	BN_clear_free(ctx->key);
	
    memset(ctx, '\0', sizeof *ctx);
    }
    
ZHJPAKE_CTX *ZHJPAKE_CTX_new(const BIGNUM *g, const BIGNUM *q, 
			 const BIGNUM *h, const char *secret, const char *name, const char *peer_name)
    {
    ZHJPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    ZHJPAKE_CTX_init(ctx, g, q, h, secret, name, peer_name);

    return ctx;
    }    
   
void ZHJPAKE_CTX_free(ZHJPAKE_CTX *ctx)
    {
    ZHJPAKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2dec(bn));
	}

/* compute the session key*/
/* key = (y_ * (h^(-1))^secret) ^ r */
void ZHJPAKE_compute_key(ZHJPAKE_CTX *ctx)
	{
	BIGNUM *t1 = BN_new();
	BIGNUM *t2 = BN_new();
	BIGNUM *inv_h = BN_new();
	
	/* inv_h = h ^ (-1) */
	BN_mod_inverse(inv_h, ctx->h, ctx->q, ctx->ctx);
	
	/* t1 = inv_h ^ secret */
	BN_mod_exp(t1, inv_h, ctx->secret, ctx->q, ctx->ctx);
	
	/* t2 = y_ * t1 */
	BN_mod_mul(t2, ctx->y_, t1, ctx->q, ctx->ctx);
	
	/* key = t2 ^ r */
	ctx->key = BN_new();
	BN_mod_exp(ctx->key, t2, ctx->r, ctx->q, ctx->ctx);
	}

const BIGNUM *ZHJPAKE_get_shared_key(ZHJPAKE_CTX *ctx)
	{
	if (ctx->key == NULL)
	{
		ZHJPAKE_compute_key(ctx);
	}
	return ctx->key;
	}
	
/* test the function of hashpassword */
void test_hash()
{
	const char *pwd1 = "123456";
	const char *pwd2 = "123457";
	BIGNUM *secret = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *q = BN_new();
	BN_set_word(q, 0xFFFFFF);
	
	printf("test hash start!\n");
	
	hashpassword(secret, pwd1, ctx, q);
	BN_print_fp(stdout, secret);
	printf("\n");
	
	hashpassword(secret, pwd2, ctx, q);
	BN_print_fp(stdout, secret);
	printf("\n");
	
	printf("test hash end!\n");
}
