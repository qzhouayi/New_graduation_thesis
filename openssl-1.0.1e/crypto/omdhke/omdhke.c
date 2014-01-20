/*
 * OMDHKE implementation
 */ 
 
#include "omdhke.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <memory.h>
#include <stdio.h>

//~ /*
 //~ * g, h and q are system parameters where q is a large prime
 //~ * which is precomputed with command line 
 //~ */	
 //~ 
//~ /* 512-bit */
static unsigned char omdhke_q[]={
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
static unsigned char omdhke_g[]={
	0x02
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


//~ // hash using
    


struct OMDHKE_Client_CTX
	{
	BN_CTX *ctx;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *PW;
	BIGNUM *x;
	BIGNUM *X;
	BIGNUM *X_star;
	BIGNUM *Kc;
	char *client_name;
	char *server_name;
	BIGNUM *shared_key;
	};

struct OMDHKE_Server_CTX
	{
	BN_CTX *ctx;
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
		
//~ static unsigned char omdhke_h[]={
	//~ 0x04
//~ };
//~ 
//~ /* given the password(string), use SHA1 to hash it and return the result mod q */
//~ static void hashpassword(BIGNUM *hash_result, const char *password, BN_CTX *ctx, const BIGNUM *q)
	//~ {
	//~ SHA_CTX sha;
	//~ size_t length = strlen(password);
	//~ BIGNUM *hash_bn = BN_new();
	//~ unsigned char digest[SHA_DIGEST_LENGTH];
	//~ 
	//~ SHA1_Init(&sha);
    //~ SHA1_Update(&sha, password, length);
    //~ SHA1_Final(digest, &sha);
    //~ BN_bin2bn(digest, SHA_DIGEST_LENGTH, hash_bn);
    //~ 
	//~ BN_mod(hash_result, hash_bn, q, ctx);
	//~ }
	//~ 
//~ static void OMDHKE_Message_init(OMDHKE_Message *message)
	//~ {
	//~ message->y = BN_new();
	//~ }
	//~ 
//~ static void OMDHKE_Message_release(OMDHKE_Message *message)
	//~ {
	//~ BN_free(message->y);
	//~ }
	//~ 
//~ void OMDHKE_Message_generate(OMDHKE_Message *message, OMDHKE_CTX *ctx)
	//~ {
	//~ BIGNUM *t1 = BN_new();
	//~ BIGNUM *t2 = BN_new();
	//~ 
	//~ /* just for debugging */
	//~ static int cnt = 0;
	//~ cnt++;
	//~ 
	//~ /* r belongs to [0, q) */
	//~ BN_rand_range(ctx->r, ctx->q);
	//~ 
	//~ /* t1 = g^r mod q */
	//~ BN_mod_exp(t1, ctx->g, ctx->r, ctx->q, ctx->ctx);
		//~ 
	//~ /* t2 = h^secret mod q */
	//~ BN_mod_exp(t2, ctx->h, ctx->secret, ctx->q, ctx->ctx);
		//~ 
	//~ /* ctx->y = t1 * t2 mod q */
	//~ BN_mod_mul(ctx->y, t1, t2, ctx->q, ctx->ctx);
		//~ 
	//~ /* message->y = ctx->y */
	//~ message->y = BN_dup(ctx->y);
	//~ 
	//~ /* print the random number r generated (just for debugging) */
	//~ if (cnt == 1)
	//~ {
	//~ print_bn("alice's r", ctx->r);
	//~ }
	//~ else
	//~ {
	//~ print_bn("bob's r", ctx->r);
	//~ }
	//~ }
//~ 
//~ OMDHKE_Message *OMDHKE_Message_new()
	//~ {
	//~ OMDHKE_Message *message = OPENSSL_malloc(sizeof *message);
//~ 
    //~ OMDHKE_Message_init(message);
//~ 
    //~ return message;
	//~ }
//~ 
//~ void OMDHKE_Message_free(OMDHKE_Message *message)
	//~ {
	//~ OMDHKE_Message_release(message);
    //~ OPENSSL_free(message);
	//~ }
	    //~ 
//~ int OMDHKE_Message_receive(OMDHKE_CTX *ctx, OMDHKE_Message *message)
	//~ {
		//~ ctx->y_ = BN_dup(message->y);
		//~ return 0;
	//~ }
	//~ 

//~ 
//~ static void OMDHKE_CTX_release(OMDHKE_CTX *ctx)
    //~ {
	
    //~ }
    //~ 
   //~ 

//~ 
//~ void print_bn(const char *name, const BIGNUM *bn)
	//~ {
	//~ printf("%s = %s\n", name, BN_bn2hex(bn));
	//~ }
//~ 
//~ /* compute the session key*/
//~ /* key = (y_ * (h^(-1))^secret) ^ r */
//~ void OMDHKE_compute_key(OMDHKE_CTX *ctx)
	//~ {
	//~ BIGNUM *t1 = BN_new();
	//~ BIGNUM *t2 = BN_new();
	//~ BIGNUM *inv_h = BN_new();
	//~ 
	//~ /* inv_h = h ^ (-1) */
	//~ BN_mod_inverse(inv_h, ctx->h, ctx->q, ctx->ctx);
	//~ 
	//~ /* t1 = inv_h ^ secret */
	//~ BN_mod_exp(t1, inv_h, ctx->secret, ctx->q, ctx->ctx);
	//~ 
	//~ /* t2 = y_ * t1 */
	//~ BN_mod_mul(t2, ctx->y_, t1, ctx->q, ctx->ctx);
	//~ 
	//~ /* key = t2 ^ r */
	//~ ctx->key = BN_new();
	//~ BN_mod_exp(ctx->key, t2, ctx->r, ctx->q, ctx->ctx);
	//~ }
//~ 
//~ const BIGNUM *OMDHKE_get_shared_key(OMDHKE_CTX *ctx)
	//~ {
	//~ if (ctx->key == NULL)
	//~ {
		//~ OMDHKE_compute_key(ctx);
	//~ }
	//~ return ctx->key;
	//~ }
	//~ 
//~ /* test the function of hashpassword */
//~ void test_hash()
//~ {
	//~ const char *pwd1 = "123456";
	//~ const char *pwd2 = "123457";
	//~ BIGNUM *secret = BN_new();
	//~ BN_CTX *ctx = BN_CTX_new();
	//~ BIGNUM *q = BN_new();
	//~ BN_set_word(q, 0xFFFFFF);
	//~ 
	//~ printf("test hash start!\n");
	//~ 
	//~ hashpassword(secret, pwd1, ctx, q);
	//~ BN_print_fp(stdout, secret);
	//~ printf("\n");
	//~ 
	//~ hashpassword(secret, pwd2, ctx, q);
	//~ BN_print_fp(stdout, secret);
	//~ printf("\n");
	//~ 
	//~ printf("test hash end!\n");
//~ }

int main() { return 0; }



static void hashstring512(SHA512_CTX *sha, const char *string)
    {
    size_t l = strlen(string);

    hashlength512(sha, l);
    SHA512_Update(sha, string, l);
    }

static void hashbn512(SHA512_CTX *sha, const BIGNUM *bn)
    {
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);

    hashlength512(sha, l);
    BN_bn2bin(bn, bin);
    SHA512_Update(sha, bin, l);
    OPENSSL_free(bin);
    }

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
	







static void hashstring256(SHA256_CTX *sha, const char *string)
    {
    size_t l = strlen(string);

    hashlength256(sha, l);
    SHA256_Update(sha, string, l);
    }

static void hashbn256(SHA256_CTX *sha, const BIGNUM *bn)
    {
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);

    hashlength256(sha, l);
    BN_bn2bin(bn, bin);
    SHA256_Update(sha, bin, l);
    OPENSSL_free(bin);
    }

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










//~ struct OMDHKE_Client_CTX
	//~ {
	//~ BIGNUM *x;
	//~ BIGNUM *X;
	//~ BIGNUM *X_star;
	//~ BIGNUM *Kc;
	//~ char *client_name;
	//~ BIGNUM *shared_key;
	//~ };

static void OMDHKE_Client_CTX_init(OMDHKE_Client_CTX *ctx,
	const char *password, const char *name)
	{
	ctx->x = BN_new();
	ctx->X = BN_new();
	ctx->X_star = BN_new();
	ctx->Kc = BN_new();
	ctx->client_name = NULL;
	ctx->shared_key = BN_new();	
	//~ ctx->g = BN_bin2bn(omdhke_g, sizeof(omdhke_g), NULL);
	//~ ctx->h = BN_bin2bn(omdhke_h, sizeof(omdhke_h), NULL);
	//~ ctx->q = BN_bin2bn(omdhke_q, sizeof(omdhke_q), NULL);
	//~ 
	//~ ctx->ctx = BN_CTX_new();
	//~ ctx->r = BN_new();
	//~ ctx->y = BN_new();
	//~ ctx->key = NULL;
	//~ ctx->y_ = NULL;
	//~ 
	//~ ctx->name = OPENSSL_strdup(name);
	//~ ctx->peer_name = OPENSSL_strdup(peer_name);
	//~ 
	//~ /* hash the given string password to get a Big Number ctx->secret */
	//~ ctx->secret = BN_new();
	//~ hashpassword(ctx->secret, password, ctx->ctx, ctx->q);
	}

static void OMDHKE_Client_CTX_release(OMDHKE_Client_CTX *ctx)
	{
	//to be filled
	BN_clear_free(ctx->x);
	BN_clear_free(ctx->X);
	BN_clear_free(ctx->X_star);
	BN_clear_free(ctx->Kc);
	OPENSSL_free(ctx->client_name);
	BN_clear_free(ctx->shared_key);
	//~ BN_clear_free(ctx->g);
	//~ BN_clear_free(ctx->h);
	//~ BN_clear_free(ctx->q);
	//~ BN_clear_free(ctx->secret);
	//~ BN_clear_free(ctx->r);
	//~ BN_clear_free(ctx->y);
	//~ BN_clear_free(ctx->y_);
	//~ BN_clear_free(ctx->key);
	//~ 
    //~ memset(ctx, '\0', sizeof *ctx);
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



//~ struct OMDHKE_Server_CTX
	//~ {
	//~ // to be filled 
	//~ char *client_name;
	//~ char *server_name;
	//~ BIGNUM *X;
	//~ BIGNUM *Y;
	//~ BIGNUM *y;
	//~ BIGNUM *X_star;
	//~ BIGNUM *Ks;
	//~ BIGNUM *Auth;
	//~ BIGNUM *shared_key;
	//~ };
	
static void OMDHKE_Server_CTX_init(OMDHKE_Server_CTX *ctx,
	const char *password, const char *name)
	{
		//to be filled
	//~ ctx->g = BN_bin2bn(omdhke_g, sizeof(omdhke_g), NULL);
	//~ ctx->h = BN_bin2bn(omdhke_h, sizeof(omdhke_h), NULL);
	//~ ctx->q = BN_bin2bn(omdhke_q, sizeof(omdhke_q), NULL);
	//~ 
	//~ ctx->ctx = BN_CTX_new();
	//~ ctx->r = BN_new();
	//~ ctx->y = BN_new();
	//~ ctx->key = NULL;
	//~ ctx->y_ = NULL;
	//~ 
	//~ ctx->name = OPENSSL_strdup(name);
	//~ ctx->peer_name = OPENSSL_strdup(peer_name);
	//~ 
	//~ /* hash the given string password to get a Big Number ctx->secret */
	//~ ctx->secret = BN_new();
	//~ hashpassword(ctx->secret, password, ctx->ctx, ctx->q);
	ctx->server_name = OPENSSL_strdup(name);
	ctx->client_name = NULL;
	ctx->X = BN_new();
	ctx->Y = BN_new();
	ctx->y = BN_new();
	ctx->X_star = BN_new();
	ctx->Ks = BN_new();
	ctx->Auth = BN_new();
	ctx->shared_key = BN_new();
	}

static void OMDHKE_Server_CTX_release(OMDHKE_Server_CTX *ctx)
	{
	//to be filled
	OPENSSL_free(ctx->server_name);
	OPENSSL_free(ctx->client_name);
	BN_clear_free(ctx->X);
	BN_clear_free(ctx->Y);
	BN_clear_free(ctx->y);
	BN_clear_free(ctx->X_star);
	BN_clear_free(ctx->Ks);
	BN_clear_free(ctx->Auth);
	BN_clear_free(ctx->shared_key);
	//~ BN_clear_free(ctx->g);
	//~ BN_clear_free(ctx->h);
	//~ BN_clear_free(ctx->q);
	//~ BN_clear_free(ctx->secret);
	//~ BN_clear_free(ctx->r);
	//~ BN_clear_free(ctx->y);
	//~ BN_clear_free(ctx->y_);
	//~ BN_clear_free(ctx->key);
	//~ 
    //~ memset(ctx, '\0', sizeof *ctx);
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



//~ struct OMDHKE_Server_Message
	//~ {
	//~ char *server_name;
	//~ BIGNUM *Y;
	//~ BIGNUM *Auth;
	//~ };
	
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
	// ctx->X = ctx->X_star / PW;
	BN_rand_range(ctx->y, ctx->q);
	BN_mod_exp(ctx->Y, ctx->g, ctx->y, ctx->q, ctx->ctx);
	BN_mod_exp(ctx->Ks, ctx->X, ctx->y, ctx->q, ctx->ctx);
	// ctx->Auth = Hash1(C, S, X_star, Y, PW, Ks);
	
	
	
	//~ unsigned char md[SHA_DIGEST_LENGTH];
    //~ SHA_CTX sha;
    //~ SHA1_Init(&sha);
    //~ hashstring(&sha, ctx->client_name);
    //~ hashstring(&sha, ctx->server_name);
    //~ hashbn(&sha, ctx->X_star);
    //~ hashbn(&sha, ctx->Y);
    //~ hashbn(&sha, ctx->PW);
    //~ hashbn(&sha, ctx->Ks);
    //~ SHA1_Final(md, &sha);
    //~ BN_bin2bn(md, SHA_DIGEST_LENGTH, message->Auth);
    
    //~ hashbn(&sha, ctx->client_name);
    //~ hashbn(&sha, p->zkpx.gr);
    //~ hashbn(&sha, p->gx);
    //~ hashstring(&sha, proof_name);
    //~ SHA1_Final(md, &sha);
    //~ BN_bin2bn(md, SHA_DIGEST_LENGTH, h);
    
	}

	
//~ OMDHKE_Client_Message *OMDHKE_Client_Message_new(OMDHKE_Client_CTX *ctx)
	//~ {
	//~ BN_rand_range(ctx->x, ctx->q);
	//~ BN_mod_exp(ctx->X, ctx->g, ctx->x, ctx->q, ctx->ctx);
	//~ 
	//~ /* Xstar = X * PW */
	//~ BN_mod_mul(ctx->X_star, ctx->X, ctx->PW, ctx->q, ctx->ctx);
	//~ 
	//~ 
	//~ 
	//~ return NULL;
	//~ }

void OMDHKE_Client_Message_generate(OMDHKE_Client_Message *message, OMDHKE_Client_CTX *ctx)
	{
	BN_rand_range(ctx->x, ctx->q);
	BN_mod_exp(ctx->X, ctx->g, ctx->x, ctx->q, ctx->ctx);
	BN_mod_mul(ctx->X_star, ctx->X, ctx->PW, ctx->q, ctx->ctx);
	message->client_name = OPENSSL_strdup(ctx->client_name);
	message->X_star = BN_dup(ctx->X_star);
	}
