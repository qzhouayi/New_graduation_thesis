/*
 * A test program to test zhjpake
 * Codes commented out are temporary code for debugging 
 */

#include <openssl/opensslconf.h> 

#ifdef OPENSSL_NO_ZHJPAKE

#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No ZHJ-PAKE support\n");
    return(0);
}

#else

#include "zhjpake.h"
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

//~ static void print_bn(const char *name, const BIGNUM *bn)
	//~ {
	//~ printf("%s = %s\n", name, BN_bn2hex(bn));
	//~ }
	//~ 
//~ static void showbn(const char *name, const BIGNUM *bn)
    //~ {
    //~ fputs(name, stdout);
    //~ fputs(" = ", stdout);
    //~ BN_print_fp(stdout, bn);
    //~ putc('\n', stdout);
    //~ }

static int run_zhjpake(ZHJPAKE_CTX *alice, ZHJPAKE_CTX *bob)
    {
    ZHJPAKE_Message *alice_message = NULL;
    ZHJPAKE_Message *bob_message = NULL;

	alice_message = ZHJPAKE_Message_new();
	ZHJPAKE_Message_generate(alice_message, alice);
	ZHJPAKE_Message_receive(bob, alice_message);
	ZHJPAKE_Message_free(alice_message);
	
	bob_message = ZHJPAKE_Message_new();
	ZHJPAKE_Message_generate(bob_message, bob);
	ZHJPAKE_Message_receive(alice, bob_message);
	ZHJPAKE_Message_free(bob_message);
	
    print_bn("Alice's key", ZHJPAKE_get_shared_key(alice));
    print_bn("Bob's key  ", ZHJPAKE_get_shared_key(bob));
	
    return 0;
    }

int main(int argc, char **argv)
    {
	//~ test_hash();
	//~ BIGNUM *prime = BN_new();
	//~ BN_generate_prime_ex(prime, 512, 1, NULL, NULL, NULL);
	//~ BN_print_fp(stdout, prime);
	//~ printf("\n");
	//~ 
    
    //~ BIGNUM *g = BN_new();
    //~ BIGNUM *q = BN_new();
    //~ BIGNUM *h = BN_new();
    //~ BIGNUM *secret = BN_new();
    //~ BIGNUM *temp = BN_new();

	//~ unsigned char md[SHA_DIGEST_LENGTH];
	//~ hashpassword(md, "123456");
	
    //~ BN_set_word(q, 19);
    //~ BN_set_word(g, 10);
    //~ BN_set_word(h, 13);
	//~ BN_set_word(secret, 5);
	//~ printf("Parameters:\n");
	//~ print_bn("q", q);
	//~ print_bn("g", g);
	//~ print_bn("h", h);
	//~ print_bn("secret", secret);
	
    //~ printf("alice's secret:");
    //~ BN_print_fp(stdout, get_secret(alice));
    //~ printf("\n");
    
    ZHJPAKE_CTX *alice;
    ZHJPAKE_CTX *bob;
    
    const int MAX_PWD_LENGTH = 50;
    char alice_pwd[MAX_PWD_LENGTH];
    char bob_pwd[MAX_PWD_LENGTH];
    
    //~ printf("input the password of Alice:\n");
    //~ fgets(alice_pwd, sizeof(alice_pwd), stdin);
    //~ alice_pwd[strlen(alice_pwd)-1] = '\0';
    //~ printf("input the password of Bob:\n");
    //~ fgets(bob_pwd, sizeof(bob_pwd), stdin);
    //~ bob_pwd[strlen(bob_pwd)-1] = '\0';
    
    strcpy(alice_pwd, "123456");
    strcpy(bob_pwd, "123456");
    
    printf("zhjpake start! (alice's pwd is %s and bob's pwd is %s)\n", alice_pwd, bob_pwd);
    
    int i;
    for (i = 0; i < 100; i++)
		{
		alice = ZHJPAKE_CTX_new(alice_pwd, "Alice", "Bob");
		bob = ZHJPAKE_CTX_new(bob_pwd, "Bob", "Alice");
		run_zhjpake(alice, bob);
		}
    
    printf("zhjpake end!\n");
    
	return 0;
    }

#endif
