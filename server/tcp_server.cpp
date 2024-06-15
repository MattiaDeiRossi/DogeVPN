#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include <map>

#include "include/socket.h"
#include "include/openssl.h"
#include "include/defines.h"
#include "include/data_structures.h"

// TODO return instead of exit.

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
        fprintf(stderr, "Client disconnect unexpectedly.\n");
        break;
    case UNEXPECTED_SOCKET_TO_DELETE:
        fprintf(stderr, "A potential connection cannot be close since socket is of wrong type.\n");
        break;
    case PWD_TOO_SHORT:
        fprintf(stderr, "Client does not have a valid password: too short.\n");
        break;
    case RAND_NOT_SUPPORTED:
        fprintf(stderr, "RAND_bytes() not supported by the current RAND method.\n");
        break;
    case RAND_FAILURE:
        fprintf(stderr, "RAND_bytes() reported a failure (%ld).\n", ERR_get_error());
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

/* Probably a thread approach would be better since SSL_accept is I/O blocking.
*  When handling a new client there is no need to just create the client socket and return.
*  A dedicated process should handle the entire process of data exchange without relying on select in the main loop.
*  After a timeout or some error the client socket can be freed along with the thread.
*  This will simplify the whole logic and the thread should create all the data without accessing shared memory. 
*  The only problem could be future portability on diffrent operating systems.
*/
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

    /* Clearing the map.
    *  Zeroing the max_socket.
    */
    map.clear();
    *max_socket = 0;
}

// TODO Assumptions ...
int map_set_max_delete_client(
    socket_holder *holder,
    std::map<socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_t *max_socket
) {

    int ret_val = 0;
    tcp_client_socket *tcs = holder->data.tcs;
    socket_t socket = tcs->socket;

    // Updating the max_socket value.
    if (socket == *max_socket) {

        // This is possible since the because the map in C++ is in increasing order of keys by default.
        auto pair = ++map.rbegin();
        socket_t max_socket_from_map = pair->first;
        *max_socket = max_socket_from_map;
    }

    /* Removing socket from the master set.
    *  Freeing the holder.
    *  Deleting freed holder reference from the map.
    */
    FD_CLR(socket, master_set);
    socket_holder_free(holder);
    map.erase(socket);

    return ret_val;
}

int map_check_socket(socket_holder *holder, socket_type type) {
    if (holder == NULL) return 0;
    if (holder->type == type) return 1;
    return 0;
}

int map_is_tss(socket_holder *holder) {
    return map_check_socket(holder, TCP_SERVER_SOCKET);
}

int map_is_uss(socket_holder *holder) {
    return map_check_socket(holder, UDP_SERVER_SOCKET);
}

int map_is_tcs(socket_holder *holder) {
    return map_check_socket(holder, TCP_CLIENT_SOCKET);
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

int ssl_read_client_credentials(SSL *ssl, client_credentials *credentials) {

    int ret_val = 0;

    client_credentials cc;
    memset(&cc, 0, sizeof(cc));

    /* The assumption here is that all the data comes from a single read.
    *  This is not the ideal solution sunce there's no guarantees that a single read can suffice.
    *  A better approach would be agreeing on maximum size and a final line indicating the end of the message.
    */
    int size = sizeof(cc.data);
    int read_error = SSL_read(ssl, cc.data, size) < 1;
    if (read_error) {
        ret_val = UNEXPECTED_DISCONNECT;
        return ret_val;
    }

    int reading_credentials = 1;
    char *usr_p = cc.username;
    char *pwd_p = cc.password;

    for (int i = 0; i < size; ++i) {
        
        char bdata = cc.data[i];
        
        if (reading_credentials) {

            // While reading credentilas alway checking if the separator is the current byte.
            if (bdata == USR_PWD_SEPARATOR) {
                reading_credentials = 0;
            } else {
                *usr_p = bdata;
                usr_p++;
            }
        } else {

            // From now on the data that is being read represents the password.
            *pwd_p = bdata;
            pwd_p++;
        }
    }

    *credentials = cc;
    return ret_val;
}

int handle_credentials_from_client(
    socket_holder *holder,
    std::map<socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_t *max_socket
) {

    int ret_val = 0;

    // This is something that should never happen.
    if (holder == NULL) exit(ILLEGAL_STATE);
    if (holder->type != TCP_CLIENT_SOCKET) exit(ILLEGAL_STATE);

    tcp_client_socket *tcs = holder->data.tcs;
    client_credentials credentials;
    ret_val = ssl_read_client_credentials(tcs->ssl, &credentials);
    if (ret_val) {
        map_set_max_delete_client(holder, map, master_set, max_socket);
        return ret_val;
    }

    /* DogeVPN requires a minimum length of bytes for the password.
    *  If the minimum length is not respected, than the database does not even gets accessed.
    */
    int pwd_len = strlen(credentials.password);
    if (pwd_len < MINIMUM_PWD_LEN) {
        ret_val = PWD_TOO_SHORT;
        map_set_max_delete_client(holder, map, master_set, max_socket);
        return ret_val;
    }

    // TODO: database fetching.
    user_id db_user_id = 42;
    char id_buf[ID_LEN];
    char *id_p = id_buf;
    memset(id_buf, 0, ID_LEN);
    sprintf(id_buf, "%d", db_user_id);

    // Generating a key to be shared with the client by using the OpenSSL library.
    unsigned char rand_buf[KEY_LEN];
    memset(rand_buf, 0, KEY_LEN);
    int rand_value = RAND_bytes(rand_buf, KEY_LEN);
    if (rand_value != 1) {

        if (rand_value == -1) {
            ret_val = RAND_NOT_SUPPORTED;
        } else {
            ret_val = RAND_FAILURE;
        }

        map_set_max_delete_client(holder, map, master_set, max_socket);
        return ret_val;
    }

    char key[KEY_LEN];
    memset(key, 0, KEY_LEN);
    memcpy(key, rand_buf, KEY_LEN);

    /* Composing the final message.
    *  It has the following form:
    *   - The first part is the key that will be used to encrypt and decrypt the data over UDP
    *   - There is a separator in the middle
    *   - The last part is the user id that it will be later on used to fetch the key that must be used
    */
    char message[MAX_KEY_MESSAGE_LEN];
    memset(message, 0, MAX_KEY_MESSAGE_LEN);
    char *msg_p = message;

    // Copying the key to the message holder.
    for (int i = 0; i < KEY_LEN; ++i) {
        *msg_p = key[i];
        msg_p++;
    }

    // Adding the separator to the message.
    *msg_p = MESSAGE_SEPARATOR;
    msg_p++;

    // Adding the final part of the message that is the user id.
    while(*id_p) {
        *msg_p = *id_p;
        msg_p++;
        id_p++;
    }

    // Writing data into socket. TODO: check error.
    SSL_write(tcs->ssl, message, strlen(message));

    /* Releasing client resources since they are not needed anymore.
    *  TODO: The id must be saved somewhere.
    */
    map_set_max_delete_client(holder, map, master_set, max_socket);

    return 0;
}

// TODO check [size].
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

        // Iterating all the registered sockets.
        for (auto iter = sh_map.begin(); iter != sh_map.end(); ++iter) {

            // Getting key and value.
            socket_t socket = iter->first;
            socket_holder *holder = iter->second;

            // Getting key and value.
           if (FD_ISSET(socket, &reads)) {

                if (map_is_tss(holder)) {

                    // Handling incoming TCP connections.
                    int tcp_client_err = handle_new_tcp_client(socket, ctx, sh_map, &master, &max_socket);
                    if (tcp_client_err) log_vpn_server_error(tcp_client_err);

                } else if (map_is_uss(holder)) {

                    // Udp server has some data to read...

                } else if (map_is_tcs(holder)) {

                    /* This part should be handled as soon as the tcp server was able to generate a client socket.
                    *  The whole logic should live inside a thread for improving performance and simplify the logic.
                    *  The only socket in the set should be the tcp and udp server socket.
                    *  This will remove the max_socket handling since select would be on tcp and udp socket only.
                    */
                    int client_data_error = handle_credentials_from_client(holder, sh_map, &master, &max_socket);
                    if (client_data_error) log_vpn_server_error(client_data_error);
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