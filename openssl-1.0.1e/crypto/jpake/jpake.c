#include "jpake.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <memory.h>

/*
 * In the definition, (xa, xb, xc, xd) are Alice's (x1, x2, x3, x4) or
 * Bob's (x3, x4, x1, x2). If you see what I mean.
 */

typedef struct
    {
    char *name;  /* Must be unique */
    char *peer_name;
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *q;
    BIGNUM *gxc; /* Alice's g^{x3} or Bob's g^{x1} */
    BIGNUM *gxd; /* Alice's g^{x4} or Bob's g^{x2} */
    } JPAKE_CTX_PUBLIC;

struct JPAKE_CTX
    {
    JPAKE_CTX_PUBLIC p;
    BIGNUM *secret;   /* The shared secret */
    BN_CTX *ctx;
    BIGNUM *xa;       /* Alice's x1 or Bob's x3 */
    BIGNUM *xb;       /* Alice's x2 or Bob's x4 */
    BIGNUM *key;      /* The calculated (shared) key */
    };

static void JPAKE_ZKP_init(JPAKE_ZKP *zkp)
    {
    zkp->gr = BN_new();
    zkp->b = BN_new();
    }

static void JPAKE_ZKP_release(JPAKE_ZKP *zkp)
    {
    BN_free(zkp->b);
    BN_free(zkp->gr);
    }

/* Two birds with one stone - make the global name as expected */
#define JPAKE_STEP_PART_init	JPAKE_STEP2_init
#define JPAKE_STEP_PART_release	JPAKE_STEP2_release

void JPAKE_STEP_PART_init(JPAKE_STEP_PART *p)
    {
    p->gx = BN_new();
    JPAKE_ZKP_init(&p->zkpx);
    }

void JPAKE_STEP_PART_release(JPAKE_STEP_PART *p)
    {
    JPAKE_ZKP_release(&p->zkpx);
    BN_free(p->gx);
    }

void JPAKE_STEP1_init(JPAKE_STEP1 *s1)
    {
    JPAKE_STEP_PART_init(&s1->p1);
    JPAKE_STEP_PART_init(&s1->p2);
    }

void JPAKE_STEP1_release(JPAKE_STEP1 *s1)
    {
    JPAKE_STEP_PART_release(&s1->p2);
    JPAKE_STEP_PART_release(&s1->p1);
    }

static void JPAKE_CTX_init(JPAKE_CTX *ctx, const char *name,
			   const char *peer_name, const BIGNUM *p,
			   const BIGNUM *g, const BIGNUM *q,
			   const BIGNUM *secret)
    {
    ctx->p.name = OPENSSL_strdup(name);
    ctx->p.peer_name = OPENSSL_strdup(peer_name);
    ctx->p.p = BN_dup(p);
    ctx->p.g = BN_dup(g);
    ctx->p.q = BN_dup(q);
    ctx->secret = BN_dup(secret);

    ctx->p.gxc = BN_new();
    ctx->p.gxd = BN_new();

    ctx->xa = BN_new();
    ctx->xb = BN_new();
    ctx->key = BN_new();
    ctx->ctx = BN_CTX_new();
    }
    
static void JPAKE_CTX_release(JPAKE_CTX *ctx)
    {
    BN_CTX_free(ctx->ctx);
    BN_clear_free(ctx->key);
    BN_clear_free(ctx->xb);
    BN_clear_free(ctx->xa);

    BN_free(ctx->p.gxd);
    BN_free(ctx->p.gxc);

    BN_clear_free(ctx->secret);
    BN_free(ctx->p.q);
    BN_free(ctx->p.g);
    BN_free(ctx->p.p);
    OPENSSL_free(ctx->p.peer_name);
    OPENSSL_free(ctx->p.name);

    memset(ctx, '\0', sizeof *ctx);
    }
    
JPAKE_CTX *JPAKE_CTX_new(const char *name, const char *peer_name,
			 const BIGNUM *p, const BIGNUM *g, const BIGNUM *q,
			 const BIGNUM *secret)
    {
    JPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    JPAKE_CTX_init(ctx, name, peer_name, p, g, q, secret);

    return ctx;
    }

void JPAKE_CTX_free(JPAKE_CTX *ctx)
    {
    JPAKE_CTX_release(ctx);
    OPENSSL_free(ctx);
    }

static void hashlength(SHA_CTX *sha, size_t l)
    {
    unsigned char b[2];

    OPENSSL_assert(l <= 0xffff);
    b[0] = l >> 8;
    b[1] = l&0xff;
    SHA1_Update(sha, b, 2);
    }

static void hashstring(SHA_CTX *sha, const char *string)
    {
    size_t l = strlen(string);

    hashlength(sha, l);
    SHA1_Update(sha, string, l);
    }

static void hashbn(SHA_CTX *sha, const BIGNUM *bn)
    {
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);

    hashlength(sha, l);
    BN_bn2bin(bn, bin);
    SHA1_Update(sha, bin, l);
    OPENSSL_free(bin);
    }

/* h=hash(g, g^r, g^x, name) */
static void zkp_hash(BIGNUM *h, const BIGNUM *zkpg, const JPAKE_STEP_PART *p,
		     const char *proof_name)
    {
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA_CTX sha;

   /*
    * XXX: hash should not allow moving of the boundaries - Java code
    * is flawed in this respect. Length encoding seems simplest.
    */
    SHA1_Init(&sha);
    hashbn(&sha, zkpg);
    OPENSSL_assert(!BN_is_zero(p->zkpx.gr));
    hashbn(&sha, p->zkpx.gr);
    hashbn(&sha, p->gx);
    hashstring(&sha, proof_name);
    SHA1_Final(md, &sha);
    BN_bin2bn(md, SHA_DIGEST_LENGTH, h);
    }

/*
 * Prove knowledge of x
 * Note that p->gx has already been calculated
 */
static void generate_zkp(JPAKE_STEP_PART *p, const BIGNUM *x,
			 const BIGNUM *zkpg, JPAKE_CTX *ctx)
    {
    BIGNUM *r = BN_new();
    BIGNUM *h = BN_new();
    BIGNUM *t = BN_new();

   /*
    * r in [0,q)
    * XXX: Java chooses r in [0, 2^160) - i.e. distribution not uniform
    */
    BN_rand_range(r, ctx->p.q);
   /* g^r */
    BN_mod_exp(p->zkpx.gr, zkpg, r, ctx->p.p, ctx->ctx);

   /* h=hash... */
    zkp_hash(h, zkpg, p, ctx->p.name);

   /* b = r - x*h */
    BN_mod_mul(t, x, h, ctx->p.q, ctx->ctx);
    BN_mod_sub(p->zkpx.b, r, t, ctx->p.q, ctx->ctx);

   /* cleanup */
    BN_free(t);
    BN_free(h);
    BN_free(r);
    }

static int verify_zkp(const JPAKE_STEP_PART *p, const BIGNUM *zkpg,
		      JPAKE_CTX *ctx)
    {
    BIGNUM *h = BN_new();
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();
    BIGNUM *t3 = BN_new();
    int ret = 0;

    zkp_hash(h, zkpg, p, ctx->p.peer_name);

   /* t1 = g^b */
    BN_mod_exp(t1, zkpg, p->zkpx.b, ctx->p.p, ctx->ctx);
   /* t2 = (g^x)^h = g^{hx} */
    BN_mod_exp(t2, p->gx, h, ctx->p.p, ctx->ctx);
   /* t3 = t1 * t2 = g^{hx} * g^b = g^{hx+b} = g^r (allegedly) */
    BN_mod_mul(t3, t1, t2, ctx->p.p, ctx->ctx);

   /* verify t3 == g^r */
    if(BN_cmp(t3, p->zkpx.gr) == 0)
	ret = 1;
    else
	JPAKEerr(JPAKE_F_VERIFY_ZKP, JPAKE_R_ZKP_VERIFY_FAILED);

   /* cleanup */
    BN_free(t3);
    BN_free(t2);
    BN_free(t1);
    BN_free(h);

    return ret;
    }    

const BIGNUM *JPAKE_get_shared_key(JPAKE_CTX *ctx)
    {
    return ctx->key;
    }

const BIGNUM *ZHJPAKE_get_shared_key(ZHJPAKE_CTX *ctx)
	{
	return ctx->key;
	}
