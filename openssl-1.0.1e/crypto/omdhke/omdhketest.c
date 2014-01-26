/*
 * A test program to test omdhke
 * Codes commented out are temporary code for debugging 
 */

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
#include <stdio.h>
#include <string.h>

/* helper function, print a bignum with its name */
static void print_bn(const char *name, const BIGNUM *bn)
	{
	printf("%s = %s\n", name, BN_bn2hex(bn));
	}

/* simulate the execution of OMDHKE */
static void run_omdhke(OMDHKE_Client_CTX *client, OMDHKE_Server_CTX *server)
    {
    OMDHKE_Client_Message *client_message = NULL;
    OMDHKE_Server_Message *server_message = NULL;

	client_message = OMDHKE_Client_Message_new();
	OMDHKE_Client_Message_generate(client_message, client);
	OMDHKE_Server_receive(server, client_message);
	OMDHKE_Client_Message_free(client_message);
	
	server_message = OMDHKE_Server_Message_new();
	OMDHKE_Server_Message_generate(server_message, server);
	if (!OMDHKE_Client_receive(client, server_message))
		{
		printf("Client Authentication fails\n");
		exit(0);
		}
	OMDHKE_Server_Message_free(server_message);
	
    print_bn("Client's key", OMDHKE_Client_get_shared_key(client));
    print_bn("Server's key", OMDHKE_Server_get_shared_key(server));
    }

int main(int argc, char **argv)
    {
    OMDHKE_Client_CTX *client;
    OMDHKE_Server_CTX *server;
    
    const int MAX_PWD_LENGTH = 50;
    char client_pwd[MAX_PWD_LENGTH];
    char server_pwd[MAX_PWD_LENGTH];
    //~ 
    //~ printf("input the password of Client:\n");
    //~ fgets(client_pwd, sizeof(client_pwd), stdin);
    //~ client_pwd[strlen(client_pwd)-1] = '\0';
    //~ printf("input the password of Server:\n");
    //~ fgets(server_pwd, sizeof(server_pwd), stdin);
    //~ server_pwd[strlen(server_pwd)-1] = '\0';

	strcpy(client_pwd, "123456");
	strcpy(server_pwd, "123456");
	
    printf("omdhke start! (client's password is %s and server's password is %s\n",
     client_pwd, server_pwd);
     
    int i;
    for (i = 0; i < 100; i++)
		{
		client = OMDHKE_Client_CTX_new(client_pwd, "Client");
		server = OMDHKE_Server_CTX_new(server_pwd, "Server");
		run_omdhke(client, server);
		}
		
    printf("omdhke end!\n");
 
    print_client_ctx(client);
    print_server_ctx(server);
    
	return 0;
    }
//~ 
//~ /* test the egcd algorithm */
//~ int main()
//~ {
	//~ BIGNUM *n = BN_new();
	//~ BIGNUM *m = BN_new();
	//~ BIGNUM *x = BN_new();
	//~ BIGNUM *y = BN_new();
	//~ 
	//~ int n_val, m_val;
	//~ while (scanf("%d%d", &n_val, &m_val) != EOF)
		//~ {
		//~ BN_set_word(n, n_val);
		//~ BN_set_word(m, m_val);
		//~ Egcd(n, m, x, y);
		//~ print_bn("x", x);
		//~ print_bn("y", y);
		//~ break;
		//~ }
	//~ 
	//~ return 0;
//~ }

#endif
