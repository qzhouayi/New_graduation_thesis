/*
 * PSPAKE implementation
 */ 
 
#include "pspake.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
//~ #include <openssl/err.h>
#include <memory.h>
#include <stdio.h>

/*
 * g, h and q are system parameters where q is a large prime
 * which is precomputed with command line 
 */	

static unsigned char pspake_g[]={
	0x02
};
static unsigned char pspake_h[]={
	0x04
};
 
//~ /* 512-bit parameter */
//~ static unsigned char pspake_q[]={
	//~ 0x99,0x54,0xE9,0x00,0xF1,0x5A,0x0C,0x73,0x8A,0x98,0x8A,0xEE,
	//~ 0x15,0xBF,0x9A,0xAA,0x06,0x6C,0x9B,0x9C,0xBE,0x99,0x36,0x51,
	//~ 0x3C,0xBA,0xC3,0x60,0x99,0xAF,0x2F,0xCC,0xBC,0xDF,0x2B,0xE8,
	//~ 0xF1,0xF4,0x0F,0xEF,0x86,0x8B,0xF8,0x42,0xF3,0xED,0x30,0xE0,
	//~ 0x15,0x3C,0xD0,0xB8,0xED,0x84,0x3A,0x85,0x97,0x5F,0xB8,0x5A,
	//~ 0xB6,0x63,0x16,0xBF,0xDF,0xD3,0xEE,0x40,0xA5,0x5E,0xDA,0xCC,
	//~ 0x9B,0x81,0xAB,0x9A,0xB4,0xBD,0x4C,0x4B,0xE3,0xE5,0xBD,0x26,
	//~ 0x48,0x89,0x69,0xEA,0xBF,0xFC,0x89,0x54,0xCE,0xF1,0x7B,0x0E,
	//~ 0xC7,0x04,0xF2,0xD1,0x88,0xD4,0x7B,0x32,0x99,0xED,0x52,0xE3,
	//~ 0x8C,0x1B,0xB8,0x53,0xB5,0xE9,0x5C,0x4B,0x63,0xC1,0xBD,0x21,
	//~ 0x90,0xBE,0xAD,0x58,0xDB,0x3E,0x60,0xCB
//~ };
/* 1024-bit parameter */
static unsigned char pspake_q[]={
	0xBB,0x94,0xE5,0x77,0xCD,0x3C,0x71,0x1B,0x3D,0x31,0x4E,0x71,
	0x8C,0x16,0xAA,0xEA,0xF2,0x47,0x7B,0x75,0xC5,0xE5,0xFA,0x23,
	0x35,0x60,0x17,0xFA,0xE0,0xBE,0x27,0xCA,0xA5,0xDD,0xE3,0x3A,
	0xEC,0xE0,0x6E,0x47,0xD1,0x5B,0x37,0x2D,0x6B,0x23,0x9C,0x75,
	0x8F,0xF5,0x90,0xAF,0x6C,0x77,0x11,0x4D,0xF5,0x72,0x83,0xF6,
	0xCA,0xBA,0x15,0x96,0x08,0xF8,0x94,0xD4,0x8F,0x7C,0x50,0xC6,
	0x3C,0x5A,0x5F,0x54,0x94,0x2F,0x0C,0x67,0x5C,0x69,0x5E,0x07,
	0xDA,0xDB,0x99,0xE0,0x00,0x10,0x52,0xF5,0x81,0xF3,0x53,0x90,
	0x73,0xBB,0xF2,0x79,0x80,0x20,0x7D,0xA6,0xC1,0x93,0x79,0x9F,
	0x58,0xB6,0xBF,0x1E,0x6B,0xEA,0x0F,0xBC,0x3E,0x8E,0x8C,0x8D,
	0x31,0xC7,0x17,0xC5,0x28,0x68,0xB3,0x83
};

struct PSPAKE_CTX
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
	};
	
struct PSPAKE_Message
	{
	BIGNUM *y;
	};

static void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2hex(bn));
	}
	
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
	
static void PSPAKE_Message_init(PSPAKE_Message *message)
	{
	message->y = BN_new();
	}
	
static void PSPAKE_Message_release(PSPAKE_Message *message)
	{
	BN_free(message->y);
	}
	
void PSPAKE_Message_generate(PSPAKE_Message *message, PSPAKE_CTX *ctx)
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

PSPAKE_Message *PSPAKE_Message_new()
	{
	PSPAKE_Message *message = OPENSSL_malloc(sizeof *message);

    PSPAKE_Message_init(message);

    return message;
	}

void PSPAKE_Message_free(PSPAKE_Message *message)
	{
	PSPAKE_Message_release(message);
    OPENSSL_free(message);
	}
	    
int PSPAKE_Message_receive(PSPAKE_CTX *ctx, PSPAKE_Message *message)
	{
	ctx->y_ = BN_dup(message->y);
	return 0;
	}
	
static void PSPAKE_CTX_init(PSPAKE_CTX *ctx, const char *password, const char *name, const char *peer_name)
	{	
	ctx->g = BN_bin2bn(pspake_g, sizeof(pspake_g), NULL);
	ctx->h = BN_bin2bn(pspake_h, sizeof(pspake_h), NULL);
	ctx->q = BN_bin2bn(pspake_q, sizeof(pspake_q), NULL);
	
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

static void PSPAKE_CTX_release(PSPAKE_CTX *ctx)
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
    
PSPAKE_CTX *PSPAKE_CTX_new(const char *secret, const char *name, const char *peer_name)
    {
    PSPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    PSPAKE_CTX_init(ctx, secret, name, peer_name);

    return ctx;
    }    
   
void PSPAKE_CTX_free(PSPAKE_CTX *ctx)
    {
    PSPAKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

/* compute the session key*/
/* key = (y_ * (h^(-1))^secret) ^ r */
void PSPAKE_compute_key(PSPAKE_CTX *ctx)
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

const BIGNUM *PSPAKE_get_shared_key(PSPAKE_CTX *ctx)
	{
	if (ctx->key == NULL)
	{
		PSPAKE_compute_key(ctx);
	}
	return ctx->key;
	}
	
// obsoleted
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

void print_ctx(const PSPAKE_CTX *ctx)
	{
	print_bn("g", ctx->g);
	print_bn("h", ctx->h);
	print_bn("secret", ctx->secret);
	print_bn("r", ctx->r);
	print_bn("key", ctx->key);
	print_bn("y", ctx->y);
	print_bn("y_", ctx->y_);
	}
