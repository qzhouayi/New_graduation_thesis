/*
 * ZHJPAKE implementation
 */ 
 
#include "zhjpake.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
//~ #include <openssl/err.h>
#include <memory.h>
#include <stdio.h>

/*
 * g, h and q are system parameters where q is a large prime
 * which is precomputed with command line 
 */	
 
/* 512-bit */
static unsigned char zhjpake_q[]={
	0x99,0x54,0xE9,0x00,0xF1,0x5A,0x0C,0x73,0x8A,0x98,0x8A,0xEE,
	0x15,0xBF,0x9A,0xAA,0x06,0x6C,0x9B,0x9C,0xBE,0x99,0x36,0x51,
	0x3C,0xBA,0xC3,0x60,0x99,0xAF,0x2F,0xCC,0xBC,0xDF,0x2B,0xE8,
	0xF1,0xF4,0x0F,0xEF,0x86,0x8B,0xF8,0x42,0xF3,0xED,0x30,0xE0,
	0x15,0x3C,0xD0,0xB8,0xED,0x84,0x3A,0x85,0x97,0x5F,0xB8,0x5A,
	0xB6,0x63,0x16,0xBF,0xDF,0xD3,0xEE,0x40,0xA5,0x5E,0xDA,0xCC,
	0x9B,0x81,0xAB,0x9A,0xB4,0xBD,0x4C,0x4B,0xE3,0xE5,0xBD,0x26,
	0x48,0x89,0x69,0xEA,0xBF,0xFC,0x89,0x54,0xCE,0xF1,0x7B,0x0E,
	0xC7,0x04,0xF2,0xD1,0x88,0xD4,0x7B,0x32,0x99,0xED,0x52,0xE3,
	0x8C,0x1B,0xB8,0x53,0xB5,0xE9,0x5C,0x4B,0x63,0xC1,0xBD,0x21,
	0x90,0xBE,0xAD,0x58,0xDB,0x3E,0x60,0xCB
};
static unsigned char zhjpake_g[]={
	0x02
};
static unsigned char zhjpake_h[]={
	0x04
};

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
	
static void ZHJPAKE_CTX_init(ZHJPAKE_CTX *ctx, const char *password, const char *name, const char *peer_name)
	{
	
	ctx->g = BN_bin2bn(zhjpake_g, sizeof(zhjpake_g), NULL);
	ctx->h = BN_bin2bn(zhjpake_h, sizeof(zhjpake_h), NULL);
	ctx->q = BN_bin2bn(zhjpake_q, sizeof(zhjpake_q), NULL);
	
	ctx->ctx = BN_CTX_new();
	ctx->r = BN_new();
	ctx->y = BN_new();
	ctx->key = NULL;
	ctx->y_ = NULL;
	
	ctx->name = OPENSSL_strdup(name);
	ctx->peer_name = OPENSSL_strdup(peer_name);
	
	/* hash the given string password to get a Big Number ctx->secret */
	ctx->secret = BN_new();
	hashpassword(ctx->secret, password, ctx->ctx, ctx->q);
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
    
ZHJPAKE_CTX *ZHJPAKE_CTX_new(const char *secret, const char *name, const char *peer_name)
    {
    ZHJPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    ZHJPAKE_CTX_init(ctx, secret, name, peer_name);

    return ctx;
    }    
   
void ZHJPAKE_CTX_free(ZHJPAKE_CTX *ctx)
    {
    ZHJPAKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2hex(bn));
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
