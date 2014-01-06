#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_JPAKE

#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No J-PAKE support\n");
    return(0);
}

#else

#include <openssl/jpake.h>
#include <openssl/err.h>

static void showbn(const char *name, const BIGNUM *bn)
    {
    fputs(name, stdout);
    fputs(" = ", stdout);
    BN_print_fp(stdout, bn);
    putc('\n', stdout);
    }

static int run_jpake(ZHJPAKE_CTX *alice, ZHJPAKE_CTX *bob)
    {
    ZHJPAKE_Message alice_message;
    ZHJPAKE_Message bob_message;

	ZHJPAKE_Message_init(&alice_message);
	ZHJPAKE_Messge_generate(&alice_message, alice);
	if (!ZHJPAKE_Message_receive(bob, &alice_message))
	{
	printf("Bob fails to process Alice's step 1\n");
	return 1;
	}
	ZHJPAKE_Message_release(&alice_message);
	
	ZHJPAKE_Message_init(&bob_message);
	ZHJPAKE_generate(&bob_message, bob);
	if (!ZHJPAKE_Message_receive(alice, &bob_message))
	{
	printf("Alice fails to process Bob's step 1\n");
	return 1;
	}
	ZHJPAKE_Message_release(&bob_message);
	
    showbn("Alice's key", JPAKE_get_shared_key(alice));
    showbn("Bob's key  ", JPAKE_get_shared_key(bob));
	
    return 0;
    }

int main(int argc, char **argv)
    {
    ZHJPAKE_CTX *alice;
    ZHJPAKE_CTX *bob;
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *q = NULL;
    BIGNUM *secret = BN_new();
    BIO *bio_err;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();

    /*
    BN_hex2bn(&p, "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7");
    BN_hex2bn(&g, "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a");
    BN_hex2bn(&q, "9760508f15230bccb292b982a2eb840bf0581cf5");
    */
    /*
    p = BN_new();
    BN_generate_prime(p, 1024, 1, NULL, NULL, NULL, NULL);
    */
   /* Use a safe prime for p (that we found earlier) */
    BN_hex2bn(&p, "F9E5B365665EA7A05A9C534502780FEE6F1AB5BD4F49947FD036DBD7E905269AF46EF28B0FC07487EE4F5D20FB3C0AF8E700F3A2FA3414970CBED44FEDFF80CE78D800F184BB82435D137AADA2C6C16523247930A63B85661D1FC817A51ACD96168E95898A1F83A79FFB529368AA7833ABD1B0C3AEDDB14D2E1A2F71D99F763F");
    showbn("p", p);
    g = BN_new();
    BN_set_word(g, 2);
    showbn("g", g);
    q = BN_new();
    BN_rshift1(q, p);
    showbn("q", q);

    BN_rand(secret, 32, -1, 0);

   /* A normal run, expect this to work... */
    zhj_alice = ZHJPAKE_CTX_new(g, q, h, secret);
    zhj_bob = ZHJPAKE_CTX_new(g, q, h, secret);
    
    if(run_zhjpake(alice, bob) != 0)
	{
	fprintf(stderr, "Plain JPAKE run failed\n");
	return 1;
	}

    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks(bio_err);

    return 0;
    }

#endif
