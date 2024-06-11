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

// *** Start C++ utilities - replace with C Map ***
#include <map>
// *** End C++ utilities ***

/* In order to generate a self signed certificate:
*   - openssl req -x509 -newkey rsa:2048 -nodes -sha256 -keyout key.pem -out cert.pem -days 365
*  *** Start SSL headers ***
*/
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
#define ILLEGAL_STATE 21
#define SELECT_ERROR 22
#define UNEXPECTED_DISCONNECT 23
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

// *** Start constants ***
#define TRUE 1
// *** End constants ***

// *** Start type definitions ***
typedef int socket_t;

typedef enum {
  TCP_SERVER_SOCKET,
  TCP_CLIENT_SOCKET,
  UDP_SERVER_SOCKET
} socket_type;

typedef struct {
    socket_t socket;
    socklen_t client_len;
    struct sockaddr_storage client_address;
    SSL *ssl;    
} tcp_client_socket;

typedef struct {
    socket_t socket;
} tcp_server_socket;

typedef struct {
    socket_t socket;
} udp_server_socket;

typedef union {
    tcp_client_socket *tcs;
    tcp_server_socket *tss;
    udp_server_socket *uss;
} socket_data;

typedef struct {
    socket_data data;
    socket_type type;
} socket_holder;
// *** End type definitions ***

int get_errno() {
    return errno;
}

int invalid_socket(socket_t socket) {
    return socket < 0;
}

void close_socket(socket_t socket) {
    close(socket);
}

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
            get_errno()
        );
        break;
    case TCP_BIND_ERROR:
        fprintf(
            stderr, 
            "TCP server cannot be bound. Call to bind() failed with error=%d.\n", 
            get_errno()
        );
        break;
    case TCP_LISTEN_ERROR:
        fprintf(
            stderr, 
            "TCP cannot listen. Call to listen() failed with error=%d.\n", 
            get_errno()
        );
        break;
    case TCP_ACCEPT_ERROR:
        fprintf(
            stderr, 
            "TCP cannot accept. Call to accept() failed with error=%d.\n", 
            get_errno()
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
            get_errno()
        );
        break;
    case UDP_BIND_ERROR:
        fprintf(
            stderr, 
            "UDP server cannot be bound. Call to bind() failed with error=%d.\n", 
            get_errno()
        );
        break;
    case ILLEGAL_STATE:
        fprintf(stderr, "Program reached an illegal state and should be aborted.\n");
        break;
    case SELECT_ERROR:
        fprintf(
            stderr, 
            "Call to select() failed with error=%d.\n", 
            get_errno()
        );
        break;
    case UNEXPECTED_DISCONNECT:
        fprintf(
            stderr, 
            "Call to select() failed with error=%d.\n", 
            get_errno()
        );
        break;
      default:
        fprintf(stderr, "Some error occured.\n");
    }
}

/* Function to call whenever a SSL contect is needed. 
*  It can be resued for all the connections.
*/
int init_ssl(SSL_CTX **ctx_pointer) {

    // This is required to initialize the OpenSSL.
    SSL_library_init();

    /* This cause OpenSSL to load all available algorithms. 
    *  A better alternative is loading only the needed ones.
    */
    OpenSSL_add_all_algorithms();

    /* This cause OpenSSL to load error strings: 
    *   - it is used just to see readable error messages when something goes wrong
    */
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return INIT_SSL_ERROR;

    int load_certificate = SSL_CTX_use_certificate_file(ctx, "cert.pem" , SSL_FILETYPE_PEM);
    int load_private_key = SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

    if (!load_certificate || !load_private_key) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return SSL_CERTIFICATE_ERROR;
    }

    *ctx_pointer = ctx;
    return 0;
}

void ssl_free(SSL *ssl) {

    // TODO: Add note of fast shutdown and truncation attack.
    SSL_shutdown(ssl);
    SSL_free(ssl);
} 

socket_t extract_socket(socket_holder *holder) {

    socket_type type = holder->type;
    switch (type) {
    case TCP_CLIENT_SOCKET:
        return (holder->data).tcs->socket;
    case TCP_SERVER_SOCKET:
        return (holder->data).tss->socket;
    case UDP_SERVER_SOCKET:
        return (holder->data).uss->socket;
    default:
        exit(ILLEGAL_STATE);
    }

    return -1;
}

int create_tcs(
    socket_t tcp_socket,
    SSL_CTX *ctx, 
    tcp_client_socket **tcs
) {

    int ret_val = 0;

    // Classic accept phase.
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    socket_t client_socket = accept(tcp_socket, (struct sockaddr*) &client_address, &client_len);
    if (invalid_socket(client_socket)) return TCP_ACCEPT_ERROR;
    
    // Creating an SSL object.
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        close_socket(client_socket);
        return SSL_CREATION_ERROR;
    }

    // Associating the ssl object with the client socket.
    SSL_set_fd(ssl, client_socket);

    /* A call to SSL_accept() can fail for many reasons. 
    *  For example if the connected client does not trust our certificate.
    *  Or the client and the server cannot agree on a cipher suite. 
    *  This must be taking into account a the server should continue listening to incoming connections.
    */
    if (SSL_accept(ssl) != 1) {

        // Loggin errors.
        ERR_print_errors_fp(stderr);

        // Cleaning up SSL resources and the useless client socket.  
        ssl_free(ssl);
        close_socket(client_socket);

        return SSL_ACCEPT_ERROR;
    }

    tcp_client_socket *ret_data = (tcp_client_socket *) malloc(sizeof(tcp_client_socket));
    if (!ret_data) {
        ssl_free(ssl);
        close_socket(client_socket);

        return OUT_OF_MEMORY;
    }

    // Logging client ip address and the established cipher.
    char buffer[256];
    struct sockaddr *cl_address = (struct sockaddr*) &client_address;
    getnameinfo(cl_address, client_len, buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST);
    printf("New connection from %s wth cipher %s\n", buffer, SSL_get_cipher(ssl));

    // Setting up tcp client socket.
    ret_data->socket = client_socket;
    ret_data->client_len = client_len;
    ret_data->client_address = client_address;
    ret_data->ssl = ssl;
    *tcs = ret_data;

    return ret_val;
}

void tcs_free(tcp_client_socket *tcs) {

    // Sanity check.
    if (tcs == NULL) return;

    ssl_free(tcs->ssl);
    close_socket(tcs->socket);
    free(tcs);
}

void clear_socket_resource(fd_set *master, socket_t socket_to_clean) {

    FD_CLR(socket_to_clean, master);
    close_socket(socket_to_clean);
}

/* A TCP server and a UDP server share some common logic when creating a socket.
*  In particular, both of them should typically perfrom the following operations:
*   - getaddrinfo()
*   - socket()
*   - bind() 
*/
int up_to_bind(int is_tcp, char const *host, char const *port, socket_t *ret_socket) {


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

    socket_t socket_listen = socket(
        bind_address->ai_family, 
        bind_address->ai_socktype,
        bind_address->ai_protocol
    );

    if (invalid_socket(socket_listen)) {
        int socket_error = is_tcp ? TCP_SOCKET_ERROR : UDP_SOCKET_ERROR;
        freeaddrinfo(bind_address);
        return socket_error;
    }

    printf("*** Binding %s socket ***\n", is_tcp ? "TCP" : "UDP");

    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        int bind_error = is_tcp ? TCP_BIND_ERROR : UDP_BIND_ERROR;
        close_socket(socket_listen);
        freeaddrinfo(bind_address);
        return bind_error;
    }

    // Address infos are no longer needed.
    freeaddrinfo(bind_address);

    // Returning correctly created socket.
    *ret_socket = socket_listen;
    return 0;
}

int create_tss(
    char const *host, 
    char const *port, 
    unsigned int max_cnts, 
    tcp_server_socket **tcp_socket
) {

    int ret_val = 0;
    
    socket_t socket;
    ret_val = up_to_bind(1, host, port, &socket);
    if (ret_val) return ret_val;

    printf("*** Making TCP socket listening for connections ***\n");

    /* Listen put the socket in a state where it listens for new connections.
    *  The max_connections parameter tells how many connections it is allowed to queue up. 
    *  If connections become queued up, then the operating system will reject new connections.
    */
    if (listen(socket, max_cnts) < 0) {
        close_socket(socket);
        return TCP_LISTEN_ERROR;
    }

    tcp_server_socket *ret_data = (tcp_server_socket *) malloc(sizeof(tcp_server_socket));
    if (!ret_data) {
        close_socket(socket);
        return OUT_OF_MEMORY;
    }

    // Setting up the tcp server socket.
    ret_data->socket = socket;
    *tcp_socket = ret_data;

    return ret_val;
}

void tss_free(tcp_server_socket *tss) {

    // Sanity check.
    if (tss == NULL) return;

    close_socket(tss->socket);
    free(tss);
}

int create_uss(char const *host, char const *port, udp_server_socket **udp_socket) {

    int ret_val = 0;

    /* A UDP socket does not need to set itself to a listen state.
    *  Just up to bind. 
    */
    socket_t socket;
    ret_val = up_to_bind(0, host, port, &socket);
    if (ret_val) return ret_val;

    udp_server_socket *uss = (udp_server_socket *) malloc(sizeof(udp_server_socket));
    if (!uss) {
        close_socket(socket);
        return OUT_OF_MEMORY;
    }

    // Setting up the udp server socket.
    uss->socket = socket;
    *udp_socket = uss;

    return ret_val;
}

void uss_free(udp_server_socket *udp_socket) {

    // Sanity check.
    if (udp_socket == NULL) return;

    close_socket(udp_socket->socket);
    free(udp_socket);
}

void socket_data_free(socket_type type, socket_data data) {

    switch (type) {
    case TCP_CLIENT_SOCKET:
        tcs_free(data.tcs);
        break;
    case TCP_SERVER_SOCKET:
        tss_free(data.tss);
        break;
    case UDP_SERVER_SOCKET:
        uss_free(data.uss);
        break;
    default:
        exit(ILLEGAL_STATE);
    }
}

int create_sh(socket_type type, socket_data data, socket_holder **sh) {

    int ret_val = 0;

    socket_holder *holder = (socket_holder *) malloc(sizeof(socket_holder));
    if (!holder) {
        ret_val = OUT_OF_MEMORY;
        socket_data_free(type, data);
        return ret_val;
    }

    holder->data = data;
    holder->type = type;
    *sh = holder;

    return ret_val;
}

void socket_holder_free(socket_holder *sh) {

    // Sanity check.
    if (sh == NULL) return;

    socket_data_free(sh->type, sh->data);
    free(sh);
}

int create_tss_sh(
    char const *host, 
    char const *port, 
    unsigned int max_cnts,
    socket_holder **sh
) {

    int ret_val = 0;

    // Creating tcp server socket.
    tcp_server_socket *tss;
    ret_val = create_tss(host, port, max_cnts, &tss);
    if (ret_val) return ret_val;

    socket_holder *holder;
    socket_data data;
    data.tss = tss;
    ret_val = create_sh(TCP_SERVER_SOCKET, data, &holder);
    if (ret_val) return ret_val;

    *sh = holder;

    return ret_val;
}

int create_uss_sh(
    char const *host, 
    char const *port, 
    socket_holder **sh
) {

    int ret_val = 0;

    // Creating udp server socket.
    udp_server_socket *uss;
    ret_val = create_uss(host, port, &uss);
    if (ret_val) return ret_val;

    socket_holder *holder;
    socket_data data;
    data.uss = uss;
    ret_val = create_sh(UDP_SERVER_SOCKET, data, &holder);
    if (ret_val) return ret_val;

    *sh = holder;

    return ret_val;
}

int create_tcs_sh(
    socket_t tcp_server_socket,
    SSL_CTX *ctx,
    socket_holder **sh
) {

    int ret_val = 0;

    // Creating tcp client socket.
    tcp_client_socket *tcs;
    ret_val = create_tcs(tcp_server_socket, ctx, &tcs);
    if (ret_val) return ret_val;

    socket_holder *holder;
    socket_data data;
    data.tcs = tcs;
    ret_val = create_sh(TCP_CLIENT_SOCKET, data, &holder);
    if (ret_val) return ret_val;

    *sh = holder;

    return ret_val;
}

void map_set_max_add(
    std::map<socket_t, socket_holder*>& map, 
    fd_set *set,
    socket_holder *holder,
    socket_t *max_socket
) {

    // Assuming extract_socket does not retun -1.
    socket_t socket = extract_socket(holder);

    // Updating the max_socket variable.
    if (socket > *max_socket) {
        *max_socket = socket;
    }

    // Adding a new socket to handle to the master set.
    FD_SET(socket, set);

    // Keeping track of the holder for further usage.
    map[socket] = holder;
}

void ssl_context_free(SSL_CTX *ctx) {
    if (ctx != NULL) SSL_CTX_free(ctx);
}

void map_set_max_free(
    std::map<socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_t *max_socket
) {

    for (auto iter = map.begin(); iter != map.end(); ++iter) {

        // Getting key and value.
        socket_t socket = iter->first;
        socket_holder *holder = iter->second;

        // Removing socket from the master set and freeing the holder.
        FD_CLR(socket, master_set);
        socket_holder_free(holder);
    }

    // Max socket returns to be zero.
    *max_socket = 0;
}

int map_check_socket(
    socket_t socket,
    socket_type type,
    std::map<socket_t, socket_holder*>& map
) {

    socket_holder *holder = map.at(socket);

    if (holder == NULL) return 0;
    if (holder->type == type) return 1;
    return 0;
}

int map_is_tss(socket_t socket, std::map<socket_t, socket_holder*>& map) {
    return map_check_socket(socket, TCP_SERVER_SOCKET, map);
}

int map_is_uss(socket_t socket, std::map<socket_t, socket_holder*>& map) {
    return map_check_socket(socket, UDP_SERVER_SOCKET, map);
}

int map_is_tcs(socket_t socket, std::map<socket_t, socket_holder*>& map) {
    return map_check_socket(socket, TCP_CLIENT_SOCKET, map);
}

int handle_new_tcp_client(
    socket_t tcp_server_socket,
    SSL_CTX *ctx,
    std::map<socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_t *max_socket
) {

    int ret_val = 0;

    socket_holder *tcs_holder;
    ret_val = create_tcs_sh(tcp_server_socket, ctx, &tcs_holder);
    if (ret_val) return ret_val;
    map_set_max_add(map, master_set, tcs_holder, max_socket);

    return ret_val;
}

int handle_credentials_from_client(socket_holder *holder) {

    int ret_val = 0;

    // This is something that should never happen.
    if (holder->type != TCP_CLIENT_SOCKET) exit(ILLEGAL_STATE);

    tcp_client_socket *tcs = holder->data.tcs;

    char credentials[1024];
    int bytes_read = SSL_read(tcs->ssl, credentials, sizeof(credentials));

    if (bytes_read < 1) {
        ret_val = UNEXPECTED_DISCONNECT;
        return ret_val;
    }

    char const *key = "this_is_a_super_secret_key";
    SSL_write(tcs->ssl, key, strlen(key));

    return 0;
}

int start_doge_vpn() {

    int ret_val = 0;
    socket_t max_socket = 0;

    SSL_CTX *ctx = NULL;
    socket_holder *tss_holder = NULL;
    socket_holder *uss_holder = NULL;

    std::map<socket_t, socket_holder*> sh_map;
    fd_set master;

    // SSL initialization.
    ret_val = init_ssl(&ctx);
    if (ret_val) goto error_handler;

    // Initialization of master set for further selects.
    FD_ZERO(&master);

    // Initialization of the tcp server socket.
    ret_val = create_tss_sh(TCP_HOST, TCP_PORT, MAX_TCP_CONNECTIONS, &tss_holder);
    if (ret_val) goto error_handler;
    map_set_max_add(sh_map, &master, tss_holder, &max_socket);

    // Initialization of the udp server socket.
    ret_val = create_uss_sh(UDP_HOST, UDP_PORT, &uss_holder);
    if (ret_val) goto error_handler;
    map_set_max_add(sh_map, &master, uss_holder, &max_socket);

    while(TRUE) {

        // Copy of master, otherwise we would lose its data.
        fd_set reads;
        reads = master;

        if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
            ret_val = SELECT_ERROR;
            goto error_handler;
        }

        // Instead of looping like so, the map can be used instead.
        socket_t i;
        for(i = 0; i <= max_socket; ++i) {

            /* Loop through the each possible socket and see wheter it was flagged by select. 
            *  If it is set FD_ISSET returns true so accept and revc won't block on a ready socket.
            */
            if (FD_ISSET(i, &reads)) {

                if (map_is_tss(i, sh_map)) {

                    // Handling incoming TCP connections.
                    int tcp_client_err = handle_new_tcp_client(i, ctx, sh_map, &master, &max_socket);
                    if (tcp_client_err) log_vpn_server_error(tcp_client_err);

                } else if (map_is_uss(i, sh_map)) {

                    // Udp server has some data to read...

                } else if (map_is_tcs(i, sh_map)) {

                    int client_data_error = handle_credentials_from_client(sh_map.at(i));
                    if (client_data_error) log_vpn_server_error(client_data_error);

                    /* For now just serving the client with whatever data it sends.
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
                    send(i, read, bytes_received, 0); */
                }

            }
        }
    }

	return 0;

error_handler:

    // Logging error.
    log_vpn_server_error(ret_val);

    // Cleaning up resources.
    ssl_context_free(ctx);
    map_set_max_free(sh_map, &master, &max_socket);

    return ret_val;
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