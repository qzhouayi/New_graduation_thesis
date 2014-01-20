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
	OMDHKE_Client_receive(client, server_message);
	OMDHKE_Server_Message_free(server_message);
	
    print_bn("Client's key", OMDHKE_Client_get_shared_key(client));
    print_bn("Server's key", OMDHKE_Server_get_shared_key(server));
    }

int main(int argc, char **argv)
    {
    OMDHKE_Client_CTX *client;
    OMDHKE_Server_CTX *server;
    
    printf("omdhke start! (client's pwd is 123456 and server's pwd is 123456\n");
    client = OMDHKE_Client_CTX_new("123456", "Client");
    server = OMDHKE_Server_CTX_new("123456", "Server");
    run_omdhke(client, server);
    printf("omdhke end!\n");
 
    
	return 0;
    }

#endif
