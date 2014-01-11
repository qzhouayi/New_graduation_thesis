#include <openssl/opensslconf.h> 

#ifdef OPENSSL_NO_OMDHKE

#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No OMDHKE support\n");
    return(0);
}

#else

#include "omdhke.h"
#include <openssl/err.h>


static void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2dec(bn));
	}
	
static void showbn(const char *name, const BIGNUM *bn)
    {
    fputs(name, stdout);
    fputs(" = ", stdout);
    BN_print_fp(stdout, bn);
    putc('\n', stdout);
    }

static int run_zhjpake(OMDHKE_CTX *alice, OMDHKE_CTX *bob)
    {
    OMDHKE_Message *alice_message = NULL;
    OMDHKE_Message *bob_message = NULL;

	alice_message = OMDHKE_Message_new();
	OMDHKE_Message_generate(alice_message, alice);
	OMDHKE_Message_receive(bob, alice_message);
	OMDHKE_Message_free(alice_message);
	
	bob_message = OMDHKE_Message_new();
	OMDHKE_Message_generate(bob_message, bob);
	OMDHKE_Message_receive(alice, bob_message);
	OMDHKE_Message_free(bob_message);
	
    print_bn("Alice's key", OMDHKE_get_shared_key(alice));
    print_bn("Bob's key  ", OMDHKE_get_shared_key(bob));
	
    return 0;
    }

int main(int argc, char **argv)
    {
	//~ test_hash();
	BIGNUM *prime = BN_new();
	BN_generate_prime_ex(prime, 512, 1, NULL, NULL, NULL);
	BN_print_fp(stdout, prime);
	printf("\n");
	
    //~ OMDHKE_CTX *alice;
    //~ OMDHKE_CTX *bob;
    //~ BIGNUM *g = BN_new();
    //~ BIGNUM *q = BN_new();
    //~ BIGNUM *h = BN_new();
    //~ BIGNUM *secret = BN_new();
    //~ BIGNUM *temp = BN_new();
//~ 
	//~ //unsigned char md[SHA_DIGEST_LENGTH];
	//~ //hashpassword(md, "123456");
	//~ 
    //~ BN_set_word(q, 19);
    //~ BN_set_word(g, 10);
    //~ BN_set_word(h, 13);
	//~ BN_set_word(secret, 5);
	//~ printf("Parameters:\n");
	//~ print_bn("q", q);
	//~ print_bn("g", g);
	//~ print_bn("h", h);
	//~ print_bn("secret", secret);
//~ 
    //~ alice = OMDHKE_CTX_new(g, q, h, "123456", "Alice", "Bob");
    //~ printf("alice's secret:");
    //~ //BN_print_fp(stdout, get_secret(alice));
    //~ printf("\n");
    //~ bob = OMDHKE_CTX_new(g, q, h, "123456", "Bob", "Alice");
    //~ //run_zhjpake(alice, bob);
    //~ 
	return 0;
    }

#endif
