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
#define TCP_BIND_ERROR 12
#define TCP_LISTEN_ERROR 13
#define TCP_ACCEPT_ERROR 14
#define SSL_CREATION_ERROR 15
#define SSL_ACCEPT_ERROR 16
#define SSL_CERTIFICATE_ERROR 17
#define OUT_OF_MEMORY 18
#define UDP_SOCKET_ERROR 19
#define UDP_BIND_ERROR 20
// ***  End error definitions ***

// *** Start TCP constant definitions ***
#define MAX_TCP_CONNECTIONS 10
#define TCP_HOST 0
#define TCP_PORT "8080"
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

// *** Start type definitions ***

typedef enum {
  TCP_SERVER_SOCKET,
  TCP_CLIENT_SOCKET,
  UDP_SERVER_SOCKET,
  UDP_CLIENT_SOCKET,
} SOCKET_TYPE;

typedef int SOCKET;

typedef struct {

    SOCKET socket_client;
    socklen_t client_len;
    struct sockaddr_storage client_address;
} client_socket;

typedef struct {

    SOCKET socket_client;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    SSL *ssl;    
} tcp_client_socket;

typedef struct {

    SOCKET socket_client;
    socklen_t client_len;
    struct sockaddr_storage client_address;
} udp_client_socket;

typedef struct {

    SOCKET socket_client;
    SOCKET_TYPE socket_type;
} socket_holder;
// *** Start type definitions ***

/*
void close_tcp_connection_with_client(tcp_client_socket *data) {

    SSL_shutdown(data->ssl);
    CLOSE_SOCKET(data->socket_client);
    SSL_free(data->ssl);
    free(data);
}*/

void log_vpn_server_error(int error_number) {

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
    case TCP_BIND_ERROR:
        fprintf(
            stderr, 
            "TCP server cannot be bound. Call to bind() failed with error=%d.\n", 
            GET_SOCKET_ERRNO()
        );
        break;
    case TCP_LISTEN_ERROR:
        fprintf(
            stderr, 
            "TCP cannot listen. Call to listen() failed with error=%d.\n", 
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
int accept_tls_client(SOCKET tcp_socket, SSL_CTX *ctx, tcp_client_socket **data) {

    // Classic accept phase.
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    SOCKET socket_client = accept(tcp_socket, (struct sockaddr*) &client_address, &client_len);
    if (!IS_VALID_SOCKET(socket_client)) {
        log_vpn_server_error(TCP_ACCEPT_ERROR);
        return TCP_ACCEPT_ERROR;
    }

    // Creating an SSL object.
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        log_vpn_server_error(SSL_CREATION_ERROR);
        CLOSE_SOCKET(socket_client);
        return SSL_CREATION_ERROR;
    }

    // Associating the ssl object with the socket_client.
    SSL_set_fd(ssl, socket_client);
    if (SSL_accept(ssl) != 1) {

        // Loggin errors.
        ERR_print_errors_fp(stderr);
        log_vpn_server_error(SSL_ACCEPT_ERROR);

        // Cleaning up SSL resources and the useless socket_client.  
        SSL_shutdown(ssl);
        CLOSE_SOCKET(socket_client);
        SSL_free(ssl);

        // No need to preallocate data if it is not necessary.
        *data = NULL;
        return SSL_ACCEPT_ERROR;
    }

    // Allocating a tcp_client_socket object.
    tcp_client_socket *ret_data = (tcp_client_socket *) malloc(sizeof(tcp_client_socket));
    if (!ret_data) {
        log_vpn_server_error(OUT_OF_MEMORY);
        return OUT_OF_MEMORY;
    }

    // Logging client ip address and the established cipher.
    char buffer[256];
    struct sockaddr *cl_address = (struct sockaddr*)&client_address;
    getnameinfo(cl_address, client_len, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);
    printf("New connection from %s wth cipher %s\n", buffer, SSL_get_cipher(ssl));

    // Setting up the client object.
    ret_data->socket_client = socket_client;
    ret_data->client_len = client_len;
    ret_data->client_address = client_address;
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
        log_vpn_server_error(INIT_SSL_ERROR);
        return INIT_SSL_ERROR;
    }

    int load_certificate = SSL_CTX_use_certificate_file(ctx, "cert.pem" , SSL_FILETYPE_PEM);
    int load_private_key = SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

    if (!load_certificate || !load_private_key) {
        ERR_print_errors_fp(stderr);
        log_vpn_server_error(SSL_CERTIFICATE_ERROR);
        SSL_CTX_free(ctx);
        return SSL_CERTIFICATE_ERROR;
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
        log_vpn_server_error(socket_error);
        freeaddrinfo(bind_address);
        return socket_error;
    }

    printf("*** Binding %s socket ***\n", is_tcp ? "TCP" : "UDP");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        int bind_error = is_tcp ? TCP_BIND_ERROR : UDP_BIND_ERROR;
        log_vpn_server_error(bind_error);
        freeaddrinfo(bind_address);
        return bind_error;
    }

    // Addres infos are no longer needed.
    freeaddrinfo(bind_address);

    // Returning correctly created socket.
    *ret_socket = socket_listen;
    return 0;
}

int create_tcp_socket(
    char const *host, char *const port, unsigned int max_cnts, SOCKET *tcp_socket
) {

    int ret_val = 0;
    
    ret_val = up_to_bind(1, host, port, tcp_socket);
    if (ret_val) return ret_val;

    /* Listen put the socket in a state where it listens for new connections.
    *  The max_connections parameter tells how many connections it is allowed to queue up. 
    *  If connections become queued up, then the operating system will reject new connections.
    */
    printf("*** Making TCP socket listening for connections ***\n");
    if (listen(*tcp_socket, max_cnts) < 0) {
        log_vpn_server_error(TCP_LISTEN_ERROR);
        return TCP_LISTEN_ERROR;
    }

    return ret_val;
}

int create_udp_socket(char const *host, char *const port, SOCKET *udp_socket) {

    /* A UDP socket does not need to set itself to a listen state.
    *  Just up to bind. 
    */
    return up_to_bind(0, host, port, udp_socket);
}

int start_clear_doge_vpn() {

    int ret_val = 0;

    // SSL initialization.
    SSL_CTX *ctx = NULL;
    ret_val = init_ssl(&ctx);
    if (ret_val) return ret_val;

    // Init set of sockets for further selects.
    fd_set master;
    FD_ZERO(&master);

    // Init tcp socket.
    SOCKET tcp_socket;
    ret_val = create_tcp_socket(TCP_HOST, TCP_PORT, MAX_TCP_CONNECTIONS, &tcp_socket);
    if (ret_val) return ret_val;

    // Init udp socket.
    SOCKET udp_socket;
    ret_val = create_udp_socket(UDP_HOST, UDP_PORT, &udp_socket);
    if (ret_val) return ret_val;

    FD_SET(tcp_socket, &master);
    FD_SET(udp_socket, &master);
    SOCKET max_socket = tcp_socket;

    while(TRUE) {

        // Copy of master, otherwise we would lose its data.
        fd_set reads;
        reads = master;

        if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
            fprintf(stderr, "select() failed. (%d)\n", GET_SOCKET_ERRNO());
            PANIC_EXIT();
        }

        SOCKET i;
        for(i = 0; i <= max_socket; ++i) {

            // Loop through the each possible socket and see wheter it was flagged by select. If
            // it is set FD_ISSET returns true so accept and revc won't block on a ready socket.
            if (FD_ISSET(i, &reads)) {

                if (i == tcp_socket) {

                    // This section will handle incoming TCP connections.
                    tcp_client_socket *res;
                    accept_tls_client(tcp_socket, ctx, &res);
                    if (!IS_VALID_SOCKET(res->socket_client)) {
                        fprintf(stderr, "accept() failed. (%d)\n", GET_SOCKET_ERRNO());
                        PANIC_EXIT();
                    }

                    add_update_sockets(&master, &max_socket, res->socket_client);

                } else {

                    // For now just serving the client with whatever data it sends.
                    char read[1024];
                    int bytes_received = recv(i, read, 1024, 0);

                    // When receiving a non-positive number, the client has disconnected.
                    // Cleaning up is mandatory.
                    if (bytes_received < 1) {

                        // This remove the socket from the master set.
                        clear_socket_resource(&master, i);
                        continue;
                    }

                    int j;
                    for (j = 0; j < bytes_received; ++j)
                        read[j] = toupper(read[j]);
                    send(i, read, bytes_received, 0);
                }

            }
        }
    }

    printf("Closing listening socket...\n");
    CLOSE_SOCKET(tcp_socket);

	return 0;
}

int start_doge_vpn() {

    return start_clear_doge_vpn();
}


int main(int argc, char const *argv[]) {
	return start_doge_vpn();
}

// A TUN interface should be created to perfrom tunnelling properly.

/*  When accepting new connections from client we must carefully keep track of what kind
*   of client_socket we are dealing with:
*       - The new client_socket is of type UDP ($1)
*       - The new client_socket is of type TCP ($2)
*   If $1:
*       - When dealing with a client udp socket, we must register all the related information
*         for using it later on, that is reading client data to forward
*       - The information to retrieve are client_id, client_ip, client_port:
*           * client_id: needed to decrypt the data with the correct key
*             (data should be encypted and authenticated). Two keys would be enough
*   If $2:
*       - Establish a TCP connection under TLS to exchange key materials for further usage under 
*         UDP
*/