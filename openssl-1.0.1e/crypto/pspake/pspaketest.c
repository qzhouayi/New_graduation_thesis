/*
 * A test program to test pspake
 * Codes commented out are temporary code for debugging 
 */

#include <openssl/opensslconf.h> 

#ifdef OPENSSL_NO_PSPAKE

#include <stdio.h>

int main(int argc, char *argv[])
{
    printf("No PSPAKE support\n");
    return(0);
}

#else

#include "pspake.h"
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

const int MAX_PWD_LENGTH = 50;

static void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2hex(bn));
	}
	
static int run_pspake(PSPAKE_CTX *alice, PSPAKE_CTX *bob)
    {
    PSPAKE_Message *alice_message = NULL;
    PSPAKE_Message *bob_message = NULL;

	alice_message = PSPAKE_Message_new();
	PSPAKE_Message_generate(alice_message, alice);
	PSPAKE_Message_receive(bob, alice_message);
	PSPAKE_Message_free(alice_message);
	
	bob_message = PSPAKE_Message_new();
	PSPAKE_Message_generate(bob_message, bob);
	PSPAKE_Message_receive(alice, bob_message);
	PSPAKE_Message_free(bob_message);
	
	BIGNUM *alice_key = PSPAKE_get_shared_key(alice);
	BIGNUM *bob_key = PSPAKE_get_shared_key(bob);
    print_bn("Alice's key", alice_key);
    print_bn("Bob's key  ", bob_key);
	
    return BN_cmp(alice_key, bob_key) == 0;
    }

static void run()
	{
	PSPAKE_CTX *alice;
    PSPAKE_CTX *bob;
    
    // input passwords from stdin    
    char alice_pwd[MAX_PWD_LENGTH];
    char bob_pwd[MAX_PWD_LENGTH];
    printf("input the password of Alice:\n");
    fgets(alice_pwd, sizeof(alice_pwd), stdin);
    alice_pwd[strlen(alice_pwd)-1] = '\0';
    printf("input the password of Bob:\n");
    fgets(bob_pwd, sizeof(bob_pwd), stdin);
    bob_pwd[strlen(bob_pwd)-1] = '\0';
    
	printf("pspake start! (alice's pwd is %s and bob's pwd is %s)\n", alice_pwd, bob_pwd);
    
    alice = PSPAKE_CTX_new(alice_pwd, "Alice", "Bob");
	bob = PSPAKE_CTX_new(bob_pwd, "Bob", "Alice");
	
	run_pspake(alice, bob);
	
	printf("alice's parameters:\n");
	print_ctx(alice);
	printf("bob's parameters:\n");
	print_ctx(bob);
	
	PSPAKE_CTX_free(alice);
	PSPAKE_CTX_free(bob);
    
    printf("pspake end!\n");
	}
	
static void run_once(const char *alice_pwd, const char *bob_pwd)
	{
	PSPAKE_CTX *alice;
    PSPAKE_CTX *bob;
    
	alice = PSPAKE_CTX_new(alice_pwd, "Alice", "Bob");
	bob = PSPAKE_CTX_new(bob_pwd, "Bob", "Alice");
	if (!run_pspake(alice, bob))
		{
		printf("authentication fails with alice's password %s and bob's password %s\n", alice_pwd, bob_pwd);
		exit(1);
		}
	PSPAKE_CTX_free(alice);
	PSPAKE_CTX_free(bob);
	}

static void test_performance()
	{
	// set passwords as constant
    const char *alice_pwd = "123456";
    const char *bob_pwd = "123456";
    
    int i;
    for (i = 0; i < 100; i++)
		{
		run_once(alice_pwd, bob_pwd);
		}
	}

void test_correctness()
	{
	FILE *pfile = fopen("pwd.txt", "r");
	char password[MAX_PWD_LENGTH];
	while (fscanf(pfile, "%s", password) != EOF)
		{
		run_once(password, password);
		}
	}
	
int main(int argc, char **argv)
    {    
    //~ test_correctness();
    //~ run_once("123456", "123456");
    test_performance();
	return 0;
    }

#endif
