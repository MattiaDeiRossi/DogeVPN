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
#define INIT_SSL_ERROR 10
#define TCP_SOCKET_ERROR 11
#define TCP_CONNECT_ERROR 12
#define TCP_ACCEPT_ERROR 14
#define TCP_SEND_ERROR 22
#define SSL_CREATION_ERROR 15
#define SSL_ACCEPT_ERROR 16
#define SSL_CERTIFICATE_ERROR 17
#define OUT_OF_MEMORY 18
#define WRONG_CREDENTIALS 21
#define UDP_SOCKET_ERROR 19
#define UDP_BIND_ERROR 20
#define TCP_READ_ERROR 23
// ***  End error definitions ***

// *** Start TCP constant definitions ***
#define MAX_TCP_CONNECTIONS 10
#define TCP_HOST 0
#define TCP_PORT "60000"
#define TCP_PORT_SERVER "8080"
// *** End TCP constant definitions ***

// *** Start UDP constant definitions ***
#define UDP_HOST 0
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
// *** End constants ***

#define SA struct sockaddr

// *** Start type definitions ***


typedef enum {
  TCP_SERVER_SOCKET,
  TCP_server_SOCKET,
  UDP_SERVER_SOCKET,
  UDP_server_SOCKET,
} SOCKET_TYPE;

typedef int SOCKET;


typedef struct {

    SOCKET socket_server;
    socklen_t server_len;
    struct sockaddr_storage server_address;
} server_socket;

typedef struct {

    SOCKET socket_server;
    socklen_t server_len;
    struct sockaddr_storage server_address;
    SSL *ssl;    
} tcp_server_socket;

typedef struct {

    SOCKET socket_server;
    socklen_t server_len;
    struct sockaddr_storage server_address;
} udp_server_socket;

typedef struct {

    SOCKET socket_server;
    SOCKET_TYPE socket_type;
} socket_holder;
// *** Start type definitions ***

/*
void close_tcp_connection_with_server(tcp_server_socket *data) {

    SSL_shutdown(data->ssl);
    CLOSE_SOCKET(data->socket_server);
    SSL_free(data->ssl);
    free(data);
}*/

void log_vpn_client_error(int error_number) {

    switch (error_number) {
      case INIT_SSL_ERROR:
        fprintf(
            stderr, 
            "Server cannot start since a valid SSL context cannot be created. Call to SSL_CTX_new() failed.\n"
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
    case TCP_ACCEPT_ERROR:
        fprintf(
            stderr, 
            "TCP cannot accept. Call to accept() failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
    case TCP_READ_ERROR:
        fprintf(
            stderr, 
            "TCP cannot read. Call to read() failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
    case WRONG_CREDENTIALS:
        fprintf(
            stderr, 
            "Wrong credentials. Authentication failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
    case SSL_CREATION_ERROR:
        fprintf(stderr, "An SSL object cannot be created. Call to SSL_new() failed.\n");
        break;
    case SSL_ACCEPT_ERROR:
        fprintf(stderr, "A valid SSL connection cannot be accepted. Call to SSL_accept() failed.\n");
        break;
    case SSL_CERTIFICATE_ERROR:
        fprintf(stderr, "A valid certificate cannot be found. Call to SSL_CTX_use_certificate_file() failed.\n");
        break;
    case OUT_OF_MEMORY:
        fprintf(stderr, "Out of memory.\n");
        break;
    case UDP_SOCKET_ERROR:
        fprintf(
            stderr, 
            "UDP server cannot be created. Call to socket() failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
    case UDP_BIND_ERROR:
        fprintf(
            stderr, 
            "UDP server cannot be bound. Call to bind() failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
      default:
        fprintf(stderr, "Some error occured.\n");
    }
}

// A call to SSL_accept() can fail for many reasons. For example if the connected client does
// not trust our certificate, or the client and the server cannot agree on a cipher
// suite. This must be taking into account a the server should continue listening to incoming
// connections.
int accept_tls_server(SOCKET tcp_socket, SSL_CTX *ctx, tcp_server_socket **data) {

    // Classic accept phase.
    struct sockaddr_storage server_address;
    socklen_t server_len = sizeof(server_address);
    SOCKET socket_server = accept(tcp_socket, (struct sockaddr*) &server_address, &server_len);
    if (!IS_VALID_SOCKET(socket_server)) {
        log_vpn_client_error(TCP_ACCEPT_ERROR);
        return TCP_ACCEPT_ERROR;
    }

    // Creating an SSL object.
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        log_vpn_client_error(SSL_CREATION_ERROR);
        CLOSE_SOCKET(socket_server);
        return SSL_CREATION_ERROR;
    }

    // Associating the ssl object with the socket_server.
    SSL_set_fd(ssl, socket_server);
    if (SSL_accept(ssl) != 1) {

        // Loggin errors.
        ERR_print_errors_fp(stderr);
        log_vpn_client_error(SSL_ACCEPT_ERROR);

        // Cleaning up SSL resources and the useless socket_server.  
        SSL_shutdown(ssl);
        CLOSE_SOCKET(socket_server);
        SSL_free(ssl);

        // No need to preallocate data if it is not necessary.
        *data = NULL;
        return SSL_ACCEPT_ERROR;
    }

    // Allocating a tcp_server_socket object.
    tcp_server_socket *ret_data = (tcp_server_socket *) malloc(sizeof(tcp_server_socket));
    if (!ret_data) {
        log_vpn_client_error(OUT_OF_MEMORY);
        return OUT_OF_MEMORY;
    }

    // Logging client ip address and the established cipher.
    char buffer[256];
    struct sockaddr *sr_address = (struct sockaddr*)&server_address;
    getnameinfo(sr_address, server_len, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);
    printf("New connection from %s wth cipher %s\n", buffer, SSL_get_cipher(ssl));

    // Setting up the client object.
    ret_data->socket_server = socket_server;
    ret_data->server_len = server_len;
    ret_data->server_address = server_address;
    ret_data->ssl = ssl;
    *data = ret_data;

    return 0;
}

void add_update_sockets(fd_set *master, SOCKET *max_socket, SOCKET new_socket) {

    // Just updating the socket set and mantain the max_socket.
    FD_SET(new_socket, master);
    if (new_socket > *max_socket) {
        *max_socket = new_socket;
    }
}

void clear_socket_resource(fd_set *master, SOCKET socket_to_clean) {

    FD_CLR(socket_to_clean, master);
    CLOSE_SOCKET(socket_to_clean);
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


    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_vpn_client_error(INIT_SSL_ERROR);
        return INIT_SSL_ERROR;
    }

    *ctx_pointer = ctx;
    return 0;
}

/* A TCP server and a UDP server share some common logic when creating a socket.
*  In particular, both of them should typically perfrom the following operations:
*   - getaddrinfo()
*   - socket()
*   - bind() 
*/
int up_to_bind(int is_tcp, char const *host, char *const port, SOCKET *ret_socket) {
    struct sockaddr_in servaddr;    
    
    printf("*** Setting up %s address info ***\n", is_tcp ? "TCP" : "UDP");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));

    /* 1. AF_INET:      Looking for IPv4 address
    *  2. SOCK_STREAM:  Going to use TCP
    *  3. AI_PASSIVE:   Will listen to any available interface
    */
    hints.ai_family = AF_INET;
    hints.ai_socktype = is_tcp ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    // The variable bind_address will hold the return information from getaddrinfo.
    struct addrinfo *bind_address;
    getaddrinfo(host, port, &hints, &bind_address);

    printf("*** Creating %s socket ***\n", is_tcp ? "TCP" : "UDP");
    SOCKET socket_listen = socket(
        bind_address->ai_family, 
        bind_address->ai_socktype,
        bind_address->ai_protocol
    );

    if (!IS_VALID_SOCKET(socket_listen)) {
        int socket_error = is_tcp ? TCP_SOCKET_ERROR : UDP_SOCKET_ERROR;
        log_vpn_client_error(socket_error);
        freeaddrinfo(bind_address);
        return socket_error;
    }

    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);

    printf("*** Binding %s socket ***\n", is_tcp ? "TCP" : "UDP");
    

    if (connect(socket_listen, (SA*)&servaddr, sizeof(servaddr))){
        int bind_error = UDP_BIND_ERROR;
        log_vpn_client_error(bind_error);
        freeaddrinfo(bind_address);
        return bind_error;
    }

    // Addres infos are no longer needed.
    freeaddrinfo(bind_address);

    // Returning correctly created socket.
    *ret_socket = socket_listen;
    return 0;
}

int create_tcp_socket(SOCKET *tcp_socket) {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
    int ret_val = 0;
    
    
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (!IS_VALID_SOCKET(sockfd)) {
        log_vpn_client_error(TCP_SOCKET_ERROR);
        return TCP_SOCKET_ERROR;
    }

    printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);
 
    // connect the client socket to server socket
    ret_val = connect(sockfd, (SA*)&servaddr, sizeof(servaddr));
    if (!IS_VALID_SOCKET(ret_val)) {
        log_vpn_client_error(TCP_CONNECT_ERROR);
        return TCP_CONNECT_ERROR;
    }
    printf("connected to the server..\n");

    *tcp_socket = sockfd;
 
    return ret_val;
}

int create_udp_socket(char const *host, char *const port, SOCKET *udp_socket) {

    /* A UDP socket does not need to set itself to a listen state.
    *  Just up to bind. 
    */
    return up_to_bind(0, host, port, udp_socket);
}

int send_credentials(SOCKET *tcp_socket){
    int ret_val = 0;
    char username[50] = "simome";
    char password[50] = "el_rubio_sgualmuzzo";
    char auth_credentials[102];
    char symm_key[100] = "";


    strcpy(auth_credentials, username);
    strcat(auth_credentials, ":"); //assicurarsi che username non possa avere :
    strcat(auth_credentials, password);
    strcat(auth_credentials, "\0");

    ret_val = send(*tcp_socket, auth_credentials, strlen(auth_credentials), 0);
    if (!IS_VALID_SOCKET(ret_val)) {
        int socket_error = TCP_SEND_ERROR;
        log_vpn_client_error(socket_error);
        return socket_error;
    }
    printf("Credentials sent correctly..\n");
    bzero(symm_key, sizeof(symm_key));
    
    ret_val = read(*tcp_socket, symm_key, sizeof(symm_key));
    if (!IS_VALID_SOCKET(ret_val)) {
        int socket_error = TCP_READ_ERROR;
        log_vpn_client_error(socket_error);
        return socket_error;
    }
    
    
    if((strncmp(symm_key, "Wrong Credentials!", 18)) == 0){ //Define with server boys what's the error given due to wrong credentials
        int socket_error = WRONG_CREDENTIALS;
        log_vpn_client_error(socket_error);
        return socket_error;
    }
    
    printf("Key received: %s\n", symm_key);

    return ret_val;
}


int start_clear_doge_vpn() {

    int ret_val = 0;

    // SSL initialization.
    SSL_CTX *ctx = NULL;
    ret_val = init_ssl(&ctx);
    if (ret_val) return ret_val;


    // Init tcp socket and credentials comunication.
    SOCKET tcp_socket;
    ret_val = create_tcp_socket(&tcp_socket);

    if (ret_val) return ret_val;
    

    do{
        ret_val = send_credentials(&tcp_socket);
        
    }
    while(ret_val == WRONG_CREDENTIALS);
    

    //Start UDP traffic with symmetric key previsously provided

    
    printf("Closing listening socket...\n");
    CLOSE_SOCKET(tcp_socket);

	return 0;
}


int main(int argc, char const *argv[]) {
    return start_clear_doge_vpn();
}

// A TUN interface should be created to perfrom tunnelling properly.

/*  When accepting new connections from client we must carefully keep track of what kind
*   of server_socket we are dealing with:
*       - The new server_socket is of type UDP ($1)
*       - The new server_socket is of type TCP ($2)
*   If $1:
*       - When dealing with a client udp socket, we must register all the related information
*         for using it later on, that is reading client data to forward
*       - The information to retrieve are server_id, server_ip, server_port:
*           * server_id: needed to decrypt the data with the correct key
*             (data should be encypted and authenticated). Two keys would be enough
*   If $2:
*       - Establish a TCP connection under TLS to exchange key materials for further usage under 
*         UDP
*/