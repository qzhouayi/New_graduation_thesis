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
    }

void test_performance()
	{
	OMDHKE_Client_CTX *client;
    OMDHKE_Server_CTX *server;
    
    // set passwords as constant
	const char *client_pwd = "123456";
	const char *server_pwd = "123456";
	
	int i;
	for (i = 0; i < 100; i++)
		{
		client = OMDHKE_Client_CTX_new(client_pwd, "Client");
		server = OMDHKE_Server_CTX_new(server_pwd, "Server");		
		run_omdhke(client, server);
		OMDHKE_Client_CTX_free(client);
		OMDHKE_Server_CTX_free(server);
		}
	}
	
void run()
	{
	OMDHKE_Client_CTX *client;
    OMDHKE_Server_CTX *server;
    
    const int MAX_PWD_LENGTH = 50;
    char client_pwd[MAX_PWD_LENGTH];
    char server_pwd[MAX_PWD_LENGTH];
    
    // input passwords from stdin
    printf("input the password of Client:\n");
    fgets(client_pwd, sizeof(client_pwd), stdin);
    client_pwd[strlen(client_pwd)-1] = '\0';
    printf("input the password of Server:\n");
    fgets(server_pwd, sizeof(server_pwd), stdin);
    server_pwd[strlen(server_pwd)-1] = '\0';
    
    printf("omdhke start! (client's password is %s and server's password is %s)\n",
     client_pwd, server_pwd);
     
	client = OMDHKE_Client_CTX_new(client_pwd, "Client");
	server = OMDHKE_Server_CTX_new(server_pwd, "Server");
		
	run_omdhke(client, server);
 
    print_client_ctx(client);
    print_server_ctx(server);
    
    OMDHKE_Client_CTX_free(client);
    OMDHKE_Server_CTX_free(server);
    
	printf("omdhke end!\n");
	}

int main(int argc, char **argv)
    {
    run();
	return 0;
    }
    
#endif
