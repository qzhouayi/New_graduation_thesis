/*
 * OMDHKE implementation
 */ 
 
#include "omdhke.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

/*
 * g, q are system parameters where q is a large prime
 * which is precomputed with command line 
 */	

static unsigned char omdhke_g[]={
	0x02
};
 
//~ /* 512-bit parameter */
//~ static unsigned char omdhke_q[]={
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
static unsigned char omdhke_q[]={
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
		

static void OMDHKE_Client_CTX_init(OMDHKE_Client_CTX *ctx,
	const char *password, const char *name);
static void OMDHKE_Client_CTX_release(OMDHKE_Client_CTX *ctx);
static void OMDHKE_Server_CTX_init(OMDHKE_Server_CTX *ctx,
	const char *password, const char *name);
static void OMDHKE_Server_CTX_release(OMDHKE_Server_CTX *ctx);

static void OMDHKE_Client_Message_init(OMDHKE_Client_Message *message);
static void OMDHKE_Client_Message_release(OMDHKE_Client_Message *message);

static void hashstring512(SHA512_CTX *sha, const char *string);
static void hashbn512(SHA512_CTX *sha, const BIGNUM *bn);
static void hashlength512(SHA512_CTX *sha, size_t l);

/* 
 * The H0 hash function in the protocol description.
 * Given parameters, hash them into a 512-bit BIGNUM.
 */
static void hash0(BIGNUM *hashresult, const char *client_name, 
				const char *server_name, const BIGNUM *X_star,
				const BIGNUM *Y, const BIGNUM *PW, const BIGNUM *K);

static void hashstring256(SHA256_CTX *sha, const char *string);
static void hashbn256(SHA256_CTX *sha, const BIGNUM *bn);
static void hashlength256(SHA256_CTX *sha, size_t l);
/* 
 * The H1 hash function in the protocol description.
 * Given parameters, hash them into a 256-bit BIGNUM.
 */
static void hash1(BIGNUM *hashresult, const char *client_name, 
				const char *server_name, const BIGNUM *X_star,
				const BIGNUM *Y, const BIGNUM *PW, const BIGNUM *K);

static void OMDHKE_Client_compute_key(OMDHKE_Client_CTX *ctx);
static void OMDHKE_Server_compute_key(OMDHKE_Server_CTX *ctx);
static BIGNUM *Egcd(const BIGNUM *n, const BIGNUM *m, BIGNUM *x, BIGNUM *y);

struct OMDHKE_Client_CTX
	{
	BN_CTX *ctx; /* used for storing temporary result in library functions*/
/* the following fields correspond to the protocol description */
	BIGNUM *q;   
	BIGNUM *g;   
	BIGNUM *PW;  
	BIGNUM *x;   
	BIGNUM *X;
	BIGNUM *Y;
	BIGNUM *X_star;
	BIGNUM *Kc;
	BIGNUM *Auth;
	char *client_name;
	char *server_name;
	BIGNUM *shared_key;
	};

struct OMDHKE_Server_CTX
	{
	BN_CTX *ctx; /* used for storing temporary result in library functions*/
/* the following fields correspond to the protocol description */	
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *PW;
	char *client_name;
	char *server_name;
	BIGNUM *X;
	BIGNUM *Y;
	BIGNUM *y;
	BIGNUM *X_star;
	BIGNUM *Ks;
	BIGNUM *Auth;
	BIGNUM *shared_key;
	};
	
struct OMDHKE_Client_Message
	{
	char *client_name;
	BIGNUM *X_star;
	};

struct OMDHKE_Server_Message
	{
	char *server_name;
	BIGNUM *Y;
	BIGNUM *Auth;
	};

/* Helper function, set number with value */
static void BN_set_val(BIGNUM *number, const BIGNUM *value)
	{
	BIGNUM *bn_zero = BN_new();
	BN_zero(bn_zero);
    BN_sub(number, value, bn_zero);
    BN_clear_free(bn_zero);
	}
	
/*
 * Extended Euclid Algorithm for Big Numbers
 */
static BIGNUM *Egcd(const BIGNUM *n, const BIGNUM *m, BIGNUM *x, BIGNUM *y)
    {
    BIGNUM *value = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();
    BIGNUM *new_m = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    if (BN_is_zero(m))
        {
        BN_set_word(x, 1);
        BN_set_word(y, 0);
        BN_set_val(value, n);
        return value;
        }    
        
    BN_mod(new_m, n, m, ctx);
	BN_set_val(value, Egcd(m, new_m, x, y));
    
    BN_set_val(temp, x);
    
	BN_set_val(x, y);
	
    /* y = temp - (n/m) * y */
    BN_div(t1, NULL, n, m, ctx);
    BN_mul(t2, t1, y, ctx);
    BN_sub(y, temp, t2);
    
    return value;
    }
		
/* 
 * Given the weak password(string), return a big number as the hash result
 * Hash method: use SHA to hash the password and then mod q
 */
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

/* add a string into the SHA context(512 bits)  */
static void hashstring512(SHA512_CTX *sha, const char *string)
    {
    size_t l = strlen(string);

    hashlength512(sha, l);
    SHA512_Update(sha, string, l);
    }

/* add a big number into the SHA context(512 bits) */
static void hashbn512(SHA512_CTX *sha, const BIGNUM *bn)
    {
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);

    hashlength512(sha, l);
    BN_bn2bin(bn, bin);
    SHA512_Update(sha, bin, l);
    OPENSSL_free(bin);
    }

/* add the length l into the SHA context(512 bits) */
static void hashlength512(SHA512_CTX *sha, size_t l)
    {
    unsigned char b[2];

    OPENSSL_assert(l <= 0xffff);
    b[0] = l >> 8;
    b[1] = l&0xff;
    SHA512_Update(sha, b, 2);
    }

/* 
 * The H0 hash function in the protocol description.
 * Given parameters, hash them into a 512-bit BIGNUM.
 */    
static void hash0(BIGNUM *hashresult, const char *client_name, 
				const char *server_name, const BIGNUM *X_star,
				const BIGNUM *Y, const BIGNUM *PW, const BIGNUM *K)
	{
	unsigned char md[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha;
    SHA512_Init(&sha);
    hashstring512(&sha, client_name);
    hashstring512(&sha, server_name);
    hashbn512(&sha, X_star);
    hashbn512(&sha, Y);
    hashbn512(&sha, PW);
    hashbn512(&sha, K);
    SHA512_Final(md, &sha);
    BN_bin2bn(md, SHA512_DIGEST_LENGTH, hashresult);
	}

/* add a string into the SHA context(256 bits) */	
static void hashstring256(SHA256_CTX *sha, const char *string)
    {
    size_t l = strlen(string);

    hashlength256(sha, l);
    SHA256_Update(sha, string, l);
    }

/* add a big number into the SHA context(256 bits) */
static void hashbn256(SHA256_CTX *sha, const BIGNUM *bn)
    {
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);

    hashlength256(sha, l);
    BN_bn2bin(bn, bin);
    SHA256_Update(sha, bin, l);
    OPENSSL_free(bin);
    }

/* add the length l into the SHA context(256 bits) */
static void hashlength256(SHA256_CTX *sha, size_t l)
    {
    unsigned char b[2];

    OPENSSL_assert(l <= 0xffff);
    b[0] = l >> 8;
    b[1] = l&0xff;
    SHA256_Update(sha, b, 2);
    }
    
/* 
 * The H1 hash function in the protocol description.
 * Given parameters, hash them into a 256-bit BIGNUM.
 */
static void hash1(BIGNUM *hashresult, const char *client_name, 
				const char *server_name, const BIGNUM *X_star,
				const BIGNUM *Y, const BIGNUM *PW, const BIGNUM *K)
	{
	unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha;
    SHA256_Init(&sha);
    hashstring256(&sha, client_name);
    hashstring256(&sha, server_name);
    hashbn256(&sha, X_star);
    hashbn256(&sha, Y);
    hashbn256(&sha, PW);
    hashbn256(&sha, K);
    SHA256_Final(md, &sha);
    BN_bin2bn(md, SHA256_DIGEST_LENGTH, hashresult);
	}

static void OMDHKE_Client_CTX_init(OMDHKE_Client_CTX *ctx,
	const char *password, const char *name)
	{
	ctx->g = BN_bin2bn(omdhke_g, sizeof(omdhke_g), NULL);
	ctx->q = BN_bin2bn(omdhke_q, sizeof(omdhke_q), NULL);
	ctx->x = BN_new();
	ctx->X = BN_new();
	ctx->X_star = BN_new();
	ctx->Kc = BN_new();
	ctx->client_name = OPENSSL_strdup(name);
	ctx->shared_key = NULL;	
	ctx->ctx = BN_CTX_new();
	
	/* hash the given string password to get a Big Number ctx->PW */
	ctx->PW = BN_new();
	hashpassword(ctx->PW, password, ctx->ctx, ctx->q);
	}

static void OMDHKE_Client_CTX_release(OMDHKE_Client_CTX *ctx)
	{
	BN_clear_free(ctx->x);
	BN_clear_free(ctx->X);
	BN_clear_free(ctx->X_star);
	BN_clear_free(ctx->Kc);
	OPENSSL_free(ctx->client_name);
	BN_clear_free(ctx->shared_key);
	
	memset(ctx, '\0', sizeof *ctx);
	}

OMDHKE_Client_CTX *OMDHKE_Client_CTX_new(const char *secret, const char *name)
	{
	OMDHKE_Client_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    OMDHKE_Client_CTX_init(ctx, secret, name);

    return ctx;
	}
	
void OMDHKE_Client_CTX_free(OMDHKE_Client_CTX *ctx)
	{
    OMDHKE_Client_CTX_release(ctx);
    OPENSSL_free(ctx);
	}

static void OMDHKE_Server_CTX_init(OMDHKE_Server_CTX *ctx,
	const char *password, const char *name)
	{
	ctx->ctx = BN_CTX_new();
	ctx->g = BN_bin2bn(omdhke_g, sizeof(omdhke_g), NULL);
	ctx->q = BN_bin2bn(omdhke_q, sizeof(omdhke_q), NULL);
	ctx->server_name = OPENSSL_strdup(name);
	ctx->client_name = NULL;
	ctx->X = BN_new();
	ctx->Y = BN_new();
	ctx->y = BN_new();
	ctx->X_star = BN_new();
	ctx->Ks = BN_new();
	ctx->Auth = BN_new();
	ctx->shared_key = NULL;
	
	/* hash the given string password to get a Big Number ctx->PW */
	ctx->PW = BN_new();
	hashpassword(ctx->PW, password, ctx->ctx, ctx->q);
	}

static void OMDHKE_Server_CTX_release(OMDHKE_Server_CTX *ctx)
	{
	OPENSSL_free(ctx->server_name);
	OPENSSL_free(ctx->client_name);
	BN_clear_free(ctx->X);
	BN_clear_free(ctx->Y);
	BN_clear_free(ctx->y);
	BN_clear_free(ctx->X_star);
	BN_clear_free(ctx->Ks);
	BN_clear_free(ctx->Auth);
	BN_clear_free(ctx->shared_key);
	
    memset(ctx, '\0', sizeof *ctx);
	}

OMDHKE_Server_CTX *OMDHKE_Server_CTX_new(const char *secret, const char *name)
	{
	OMDHKE_Server_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    OMDHKE_Server_CTX_init(ctx, secret, name);

    return ctx;
	}

void OMDHKE_Server_CTX_free(OMDHKE_Server_CTX *ctx)
	{
    OMDHKE_Server_CTX_release(ctx);
    OPENSSL_free(ctx);
	}
	
static void OMDHKE_Client_Message_init(OMDHKE_Client_Message *message)
	{
	message->client_name = NULL;
	message->X_star = BN_new();
	}

static void OMDHKE_Client_Message_release(OMDHKE_Client_Message *message)
	{
	OPENSSL_free(message->client_name);
	BN_clear_free(message->X_star);
	}

OMDHKE_Client_Message *OMDHKE_Client_Message_new()
	{
	OMDHKE_Client_Message *message = OPENSSL_malloc(sizeof *message);

    OMDHKE_Client_Message_init(message);

    return message;
	}
	
void OMDHKE_Client_Message_free(OMDHKE_Client_Message *message)
	{
	OMDHKE_Client_Message_release(message);
    OPENSSL_free(message);
	}

static void OMDHKE_Server_Message_init(OMDHKE_Server_Message *message)
	{
	message->server_name = NULL;
	message->Y = BN_new();
	message->Auth = BN_new();
	}

static void OMDHKE_Server_Message_release(OMDHKE_Server_Message *message)
	{
	OPENSSL_free(message->server_name);
	BN_clear_free(message->Y);
	BN_clear_free(message->Auth);
	}

OMDHKE_Server_Message *OMDHKE_Server_Message_new()
	{
	OMDHKE_Server_Message *message = OPENSSL_malloc(sizeof *message);

    OMDHKE_Server_Message_init(message);

    return message;
	}
	
void OMDHKE_Server_Message_free(OMDHKE_Server_Message *message)
	{
	OMDHKE_Server_Message_release(message);
    OPENSSL_free(message);
	}
	
void OMDHKE_Server_Message_generate(OMDHKE_Server_Message *message, OMDHKE_Server_CTX *ctx)
	{
	/* ctx->X = ctx->X_star / ctx->PW (mod ctx->q); */
	BIGNUM *temp_x = BN_new();
	BIGNUM *temp_y = BN_new();
	Egcd(ctx->PW, ctx->q, temp_x, temp_y);
	BN_mod_mul(ctx->X, temp_x, ctx->X_star, ctx->q, ctx->ctx);

	/* y belongs to [0, q) */
	BN_rand_range(ctx->y, ctx->q);
	
	/* Y = g^y */
	BN_mod_exp(ctx->Y, ctx->g, ctx->y, ctx->q, ctx->ctx);
	
	/* Ks = X^y */
	BN_mod_exp(ctx->Ks, ctx->X, ctx->y, ctx->q, ctx->ctx);
	
	/* Auth = H1(client_name, server_name, X_star, Y, PW, Ks) */
	hash1(ctx->Auth, ctx->client_name, ctx->server_name, ctx->X_star, ctx->Y, ctx->PW, ctx->Ks);
	
	OMDHKE_Server_compute_key(ctx);
	
	message->Auth = BN_dup(ctx->Auth);
	message->server_name = OPENSSL_strdup(ctx->server_name);
	message->Y = BN_dup(ctx->Y);
	}

void OMDHKE_Client_Message_generate(OMDHKE_Client_Message *message, OMDHKE_Client_CTX *ctx)
	{
	/* x belongs to [0, q) */
	BN_rand_range(ctx->x, ctx->q);
	/* X = g^x */
	BN_mod_exp(ctx->X, ctx->g, ctx->x, ctx->q, ctx->ctx);
	/* X_star = X * PW */
	BN_mod_mul(ctx->X_star, ctx->X, ctx->PW, ctx->q, ctx->ctx);
	message->client_name = OPENSSL_strdup(ctx->client_name);
	message->X_star = BN_dup(ctx->X_star);
	}

int OMDHKE_Server_receive(OMDHKE_Server_CTX *ctx, OMDHKE_Client_Message *message)
	{
	ctx->client_name = OPENSSL_strdup(message->client_name);
	ctx->X_star = BN_dup(message->X_star);
	return 1;
	}

/* check if the Auth field of client context is valid */	
static int isvalid(OMDHKE_Client_CTX *ctx)
	{
	BIGNUM *hashresult = BN_new();
	hash1(hashresult, ctx->client_name, ctx->server_name, ctx->X_star, ctx->Y, ctx->PW, ctx->Kc);
	return BN_cmp(ctx->Auth, hashresult) == 0;
	}
	
int OMDHKE_Client_receive(OMDHKE_Client_CTX *ctx, OMDHKE_Server_Message *message)
	{
	ctx->server_name = OPENSSL_strdup(message->server_name);
	ctx->Y = BN_dup(message->Y);
	BN_mod_exp(ctx->Kc, ctx->Y, ctx->x, ctx->q, ctx->ctx);
	ctx->Auth = BN_dup(message->Auth);
	if (!isvalid(ctx))
		return 0;
	else
		{
		OMDHKE_Client_compute_key(ctx);
		return 1;
		}
			
	}

static void OMDHKE_Client_compute_key(OMDHKE_Client_CTX *ctx)
	{
	hash0(ctx->shared_key, ctx->client_name, ctx->server_name, ctx->X_star, ctx->Y, ctx->PW, ctx->Kc);
	}
	
const BIGNUM *OMDHKE_Client_get_shared_key(OMDHKE_Client_CTX *ctx)
	{
	if (ctx->shared_key == NULL)
		{
		ctx->shared_key = BN_new();
		OMDHKE_Client_compute_key(ctx);
		}
	return ctx->shared_key;
	}

static void OMDHKE_Server_compute_key(OMDHKE_Server_CTX *ctx)
	{
	hash0(ctx->shared_key, ctx->client_name, ctx->server_name, ctx->X_star, ctx->Y, ctx->PW, ctx->Ks);
	}

const BIGNUM *OMDHKE_Server_get_shared_key(OMDHKE_Server_CTX *ctx)
	{
	if (ctx->shared_key == NULL)
		{
		ctx->shared_key = BN_new();
		OMDHKE_Server_compute_key(ctx);
		}
	return ctx->shared_key;	
	}

/* helper function, print a bignum with its name */
static void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2hex(bn));
	}

void print_server_ctx(OMDHKE_Server_CTX *ctx)
	{
	printf("server's key:\n");
	//~ print_bn("q", ctx->q);
	//~ print_bn("g", ctx->g);
	//~ print_bn("PW", ctx->PW);
	//~ printf("client_name: %s\n", ctx->client_name);
	//~ printf("server_name: %s\n", ctx->server_name);
	//~ print_bn("X", ctx->X);
	//~ print_bn("Y", ctx->Y);
	//~ print_bn("y", ctx->y);
	//~ print_bn("X_star", ctx->X_star);
	//~ print_bn("Auth", ctx->Auth);
	//~ print_bn("Ks", ctx->Ks);
	print_bn("shared_key", OMDHKE_Server_get_shared_key(ctx));
	}

void print_client_ctx(OMDHKE_Client_CTX *ctx)
	{
	printf("client's key:\n");
	//~ print_bn("q", ctx->q);
	//~ print_bn("g", ctx->g);
	//~ print_bn("PW", ctx->PW);
	//~ printf("client_name: %s\n", ctx->client_name);
	//~ printf("server_name: %s\n", ctx->server_name);
	//~ print_bn("x", ctx->x);
	//~ print_bn("X", ctx->X);
	//~ print_bn("Y", ctx->Y);
	//~ print_bn("X_star", ctx->X_star);
	//~ print_bn("Auth", ctx->Auth);
	//~ print_bn("Kc", ctx->Kc);
	print_bn("shared_key", OMDHKE_Client_get_shared_key(ctx));
	}
