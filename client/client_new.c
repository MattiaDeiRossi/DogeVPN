// Compile with gcc client.c -lssl -lcrypto -o client

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>

// *** Start SSL headers ***
// In order to generate a self signed certificate:
//  - openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout key.pem -out cert.pem -days 365
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
// *** End SSL headers ***

// ***  Start error definitions ***
#define INIT_SSL_ERROR 1000
#define TCP_SSL_NEW_ERROR 1001
#define TCP_SSL_SEXT_ERROR 1002
#define TCP_SOCKET_ERROR 2000
#define TCP_CONNECT_ERROR 2001
#define TCP_SEND_ERROR 2002
#define TCP_READ_ERROR 2003
#define WRONG_CREDENTIAL 4000

// ***  End error definitions ***

// *** Start TCP constant definitions ***
#define TCP_HOST "127.0.0.1"
#define TCP_HOST_SGUALMUZZO "0.0.0.0"
#define TCP_PORT 8080
// *** End TCP constant definitions ***

// *** Start UDP constant definitions ***
#define UDP_HOST "127.0.0.1"
#define UDP_PORT "9090"
// *** Start UDP constant definitions ***

// *** Start macros ***
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define PANIC_EXIT() exit(GET_SOCKET_ERRNO())
// *** End macros ***

// *** Start constants ***
#define TRUE 1
#define AUTH_FAILED "AuthFailed"
// *** End constants ***

#define SA struct sockaddr

typedef int SOCKET;

void log_vpn_client_error(int error_number) {

    switch (error_number) {
        case INIT_SSL_ERROR:
            fprintf(
                stderr, 
                "Client cannot start since a valid SSL context cannot be created. Call to SSL_CTX_new() failed.\n"
            );
            break;
        case TCP_SOCKET_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot be created. Call to socket() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case TCP_CONNECT_ERROR:
            fprintf(
                stderr, 
                "TCP server cannot connect. Call to connect() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );        
            break;
        case TCP_SEND_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to send() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case TCP_READ_ERROR:
            fprintf(
                stderr, 
                "TCP cannot send. Call to read() failed with error=%d.\n", 
                GET_SOCKET_ERRNO()
            );
            break;
        case WRONG_CREDENTIAL:
            fprintf(
                stderr, 
                "Wrong credentials. Authentication failed\n"
            );
            break;
        case TCP_SSL_NEW_ERROR:
            fprintf(
                stderr, 
                "Client cannot start since a valid SSL context cannot be created. Call to SSL_new() failed.\n"
            );
            break;
        case TCP_SSL_SEXT_ERROR:
            fprintf(
                stderr, 
                "Client cannot start since a valid SSL context cannot be created. Call to SSL_sext() failed.\n"
            );
            break;
        
        default:
            fprintf(stderr, "Some error occured.\n");
    }
}

// Function to call whenever a SSL contect is needed. 
// It can be resued for all the connections.
int init_ssl(SSL_CTX **ctx_pointer) {

    // This is required to initialize the OpenSSL.
    SSL_library_init();

    // This cause OpenSSL to load all available algorithms. A better alternative
    // is loading only the needed ones.
    OpenSSL_add_all_algorithms();

    // This cause OpenSSL to load error strings: it is used just to see
    // readable error messages when something goes wrong.
    SSL_load_error_strings();


    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_vpn_client_error(INIT_SSL_ERROR);
        return INIT_SSL_ERROR;
    }

    *ctx_pointer = ctx;
    return 0;
}

int create_tcp_socket(SOCKET *tcp_socket) {
    int sockfd;
    struct sockaddr_in servaddr;
    int ret_val = 0;
    
    printf("*** Setting up TCP address info ***\n");
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        log_vpn_client_error(TCP_SOCKET_ERROR);
        return TCP_SOCKET_ERROR;
    }

    printf("*** Creating TCP socket ***\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(TCP_HOST_SGUALMUZZO);
    servaddr.sin_port = htons(TCP_PORT);
    
    printf("*** Connecting TCP socket ***\n");

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr))) {
        log_vpn_client_error(TCP_CONNECT_ERROR);
        return TCP_CONNECT_ERROR;
    }   

    *tcp_socket = sockfd;
    
    return ret_val;
}

int send_credential(SOCKET *tcp_socket, char const* user, char const* pwd, SSL* ssl_session){
    int ret_val = 0;
    int size = strlen(user) + strlen(pwd) + 1;
    char *auth_credential = (char *)malloc(sizeof(char) * size);
    char symmetric_key[256];

    strcpy(auth_credential, user);
    strcat(auth_credential, ":");
    strcat(auth_credential, pwd);
    strcat(auth_credential, "\0");

    printf("*** Send authentication parameters ***\n");
    if (!SSL_write(ssl_session, auth_credential, strlen(auth_credential))) {
        log_vpn_client_error(TCP_SEND_ERROR);
        return TCP_SEND_ERROR;
    }

    bzero(symmetric_key, sizeof(symmetric_key));
    printf("*** Read authentication's response ***\n");
    if (!SSL_read(ssl_session, symmetric_key, sizeof(symmetric_key))) {
        log_vpn_client_error(TCP_READ_ERROR);
        return TCP_READ_ERROR;
    }
    
    if((strncmp(symmetric_key, AUTH_FAILED, strlen(AUTH_FAILED))) == 0) { 
        log_vpn_client_error(WRONG_CREDENTIAL);
        return WRONG_CREDENTIAL;
    }
    printf("Key received: %s\n", symmetric_key);

    return ret_val;
}

int bind_socket_to_SSL(SSL_CTX* ctx, SOCKET sock, SSL** ssl_session){
    int ret_val = 1;

    //Create new SSL session
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        log_vpn_client_error(TCP_SSL_NEW_ERROR);
        return TCP_SSL_NEW_ERROR;
    }

    //Set remote hostname to SSL session
    ret_val = SSL_set_tlsext_host_name(ssl, TCP_HOST_SGUALMUZZO);
    if (ret_val == 0) {
        log_vpn_client_error(TCP_SSL_SEXT_ERROR);
        return TCP_SSL_SEXT_ERROR;
    }

    //Bind TCP socket with SSL session
    SSL_set_fd(ssl, sock);

    //Start TLS handshake
    ret_val = SSL_connect(ssl);
    if (ret_val == -1) {
        log_vpn_client_error(TCP_SSL_SEXT_ERROR);
        return TCP_SSL_SEXT_ERROR;
    }

    printf("Using cipher: %s\n", SSL_get_cipher(ssl));

    *ssl_session = ssl;

    return 0;
}


int start_doge_vpn(char const* user, char const* pwd) {
    int ret_val = 0;

    // SSL initialization.
    SSL_CTX *ctx = NULL;
    ret_val = init_ssl(&ctx);
    if (ret_val) return ret_val;



    SOCKET tcp_socket;
    ret_val = create_tcp_socket(&tcp_socket);
    if (ret_val) return ret_val;

    SSL* ssl_session;
    ret_val = bind_socket_to_SSL(ctx, tcp_socket, &ssl_session);
    if (ret_val) return ret_val;

    ret_val = send_credential(&tcp_socket, user, pwd, ssl_session);
    if (ret_val) return ret_val;

    return ret_val;
}



int main(int argc, char const *argv[]) {
    if(argc == 3){
        return start_doge_vpn(argv[1], argv[2]);
    }
}