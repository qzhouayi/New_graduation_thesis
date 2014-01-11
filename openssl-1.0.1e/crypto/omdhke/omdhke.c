#include "omdhke.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <memory.h>
#include <stdio.h>
/*
 * OMDHKE
 */
    
struct OMDHKE_CTX
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
	
static void OMDHKE_Message_init(OMDHKE_Message *message)
	{
	message->y = BN_new();
	}
	
static void OMDHKE_Message_release(OMDHKE_Message *message)
	{
	BN_free(message->y);
	}
	
void OMDHKE_Message_generate(OMDHKE_Message *message, OMDHKE_CTX *ctx)
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

OMDHKE_Message *OMDHKE_Message_new()
	{
	OMDHKE_Message *message = OPENSSL_malloc(sizeof *message);

    OMDHKE_Message_init(message);

    return message;
	}

void OMDHKE_Message_free(OMDHKE_Message *message)
	{
	OMDHKE_Message_release(message);
    OPENSSL_free(message);
	}
	    
int OMDHKE_Message_receive(OMDHKE_CTX *ctx, OMDHKE_Message *message)
	{
		ctx->y_ = BN_dup(message->y);
		return 0;
	}
	
static void OMDHKE_CTX_init(OMDHKE_CTX *ctx, const BIGNUM *g, const BIGNUM *q, 
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

static void OMDHKE_CTX_release(OMDHKE_CTX *ctx)
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
    
OMDHKE_CTX *OMDHKE_CTX_new(const BIGNUM *g, const BIGNUM *q, 
			 const BIGNUM *h, const char *secret, const char *name, const char *peer_name)
    {
    OMDHKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    OMDHKE_CTX_init(ctx, g, q, h, secret, name, peer_name);

    return ctx;
    }    
   
void OMDHKE_CTX_free(OMDHKE_CTX *ctx)
    {
    OMDHKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2dec(bn));
	}

/* compute the session key*/
/* key = (y_ * (h^(-1))^secret) ^ r */
void OMDHKE_compute_key(OMDHKE_CTX *ctx)
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

const BIGNUM *OMDHKE_get_shared_key(OMDHKE_CTX *ctx)
	{
	if (ctx->key == NULL)
	{
		OMDHKE_compute_key(ctx);
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

DH *get_dh512()
	{
	static unsigned char dh512_p[]={
		0xBD,0x8B,0xFB,0xC4,0x41,0xF9,0x9F,0x81,0x0E,0x46,0x77,0x1D,
		0x33,0x89,0x2A,0x48,0x9B,0xAA,0x8B,0x8C,0xD9,0xC3,0xB6,0xC0,
		0x11,0x95,0x78,0x18,0x3C,0x50,0x9A,0xEC,0x6D,0x41,0xFF,0x17,
		0x75,0x30,0x08,0xBD,0xCB,0x46,0xB4,0x23,0x5E,0x22,0x9A,0x73,
		0x2B,0x3F,0x5A,0x37,0xC6,0xED,0x7A,0x72,0x60,0x74,0xCA,0x9E,
		0x6A,0x36,0xDC,0x2B,
		};
	static unsigned char dh512_g[]={
		0x02,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
	}
