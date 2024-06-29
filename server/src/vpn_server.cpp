#include "standards.h"
#include "defines.h"
#include "data_structures.h"
#include "encryption.h"
#include "utils.h"
#include "ssl_utils.h"
#include "socket_utils.h"

// TODO return instead of exit.

void log_vpn_server_error(int error_number) {

    switch (error_number) {
      case INIT_SSL_ERROR:
        fprintf(stderr, "Server cannot start since a valid SSL context cannot be created. Call to SSL_CTX_new() failed.\n");
        break;
    case TCP_SOCKET_ERROR:
        fprintf(stderr, "TCP server cannot be created. Call to socket() failed.\n");
        break;
    case TCP_BIND_ERROR:
        fprintf(stderr, "TCP server cannot be bound. Call to bind() failed.\n");
        break;
    case TCP_LISTEN_ERROR:
        fprintf(stderr, "TCP cannot listen. Call to listen() failed.\n");
        break;
    case TCP_ACCEPT_ERROR:
        fprintf(stderr, "TCP cannot accept. Call to accept() failed.\n");
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
        fprintf(stderr, "UDP server cannot be created. Call to socket() failed.\n");
        break;
    case UDP_BIND_ERROR:
        fprintf(stderr, "UDP server cannot be bound. Call to bind() failed.\n");
        break;
    case ILLEGAL_STATE:
        fprintf(stderr, "Program reached an illegal state and should be aborted.\n");
        break;
    case SELECT_ERROR:
        fprintf(stderr, "Call to select() failed.\n");
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
        fprintf(stderr, "RAND_bytes() reported a failure.\n");
        break;
    case SSL_WRITE_ERROR:
        fprintf(stderr, "SSL_write() reported a failure.\n");
        break;
    case UDP_READ_ERROR:
        fprintf(stderr, "recvfrom() reported a failure.\n");
        break;
    case INVALID_CLIENT_ID:
        fprintf(stderr, "The client id cannot be extracted from the UDP packet.\n");
        break;
    case UDP_PACKET_TOO_LARGE:
        fprintf(stderr, "UDP packet is too large.\n");
        break;
    case INVALID_IV:
        fprintf(stderr, "IV vector is not of the correct size.\n");
        break;
    case INVALID_HASH:
        fprintf(stderr, "The hash is not of the correct size.\n");
        break;
    case INVALID_MESSAGE:
        fprintf(stderr, "Message is too long.\n");
        break;
    case USER_IS_NOT_PRESENT:
        fprintf(stderr, "Key cannot be found for the give id.\n");
        break;
      default:
        fprintf(stderr, "Some error occured.\n");
    }
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
    case TUN_SERVER_SOCKET:
        return (holder->data).tun_ss->socket;
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
    if (socket_utils::invalid_socket(client_socket)) return TCP_ACCEPT_ERROR;
    
    // Creating an SSL object.
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        socket_utils::close_socket(client_socket);
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
        ssl_utils::free_ssl(ssl);
        return SSL_ACCEPT_ERROR;
    }

    tcp_client_socket *ret_data = (tcp_client_socket *) malloc(sizeof(tcp_client_socket));
    if (!ret_data) {
        ssl_utils::free_ssl(ssl);
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

    ssl_utils::free_ssl(tcs->ssl);
    free(tcs);
}

int create_tss(
    char const *host, 
    char const *port, 
    unsigned int max_cnts, 
    tcp_server_socket **tcp_socket
) {

    int ret_val = 0;
    
    socket_t socket;
    ret_val = socket_utils::bind_server_socket(true, host, port, &socket);
    if (ret_val) return ret_val;

    printf("*** Making TCP socket listening for connections ***\n");

    /* Listen put the socket in a state where it listens for new connections.
    *  The max_connections parameter tells how many connections it is allowed to queue up. 
    *  If connections become queued up, then the operating system will reject new connections.
    */
    if (listen(socket, max_cnts) < 0) {
        socket_utils::close_socket(socket);
        return TCP_LISTEN_ERROR;
    }

    tcp_server_socket *ret_data = (tcp_server_socket *) malloc(sizeof(tcp_server_socket));
    if (!ret_data) {
        socket_utils::close_socket(socket);
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

    socket_utils::close_socket(tss->socket);
    free(tss);
}

int create_uss(char const *host, char const *port, udp_server_socket **udp_socket) {

    int ret_val = 0;

    /* A UDP socket does not need to set itself to a listen state.
    *  Just up to bind. 
    */
    socket_t socket;
    ret_val = socket_utils::bind_server_socket(false, host, port, &socket);
    if (ret_val) return ret_val;

    udp_server_socket *uss = (udp_server_socket *) malloc(sizeof(udp_server_socket));
    if (!uss) {
        socket_utils::close_socket(socket);
        return OUT_OF_MEMORY;
    }

    // Setting up the udp server socket.
    uss->socket = socket;
    *udp_socket = uss;

    return ret_val;
}

int create_tun_ss(tun_server_socket **tun_socket) {

    int ret_val = 0;

    // TODO

    return ret_val;
}

void uss_free(udp_server_socket *udp_socket) {

    // Sanity check.
    if (udp_socket == NULL) return;

    socket_utils::close_socket(udp_socket->socket);
    free(udp_socket);
}

void tun_ss_free(tun_server_socket *tun_socket) {

    // Sanity check.
    if (tun_socket == NULL) return;

    socket_utils::close_socket(tun_socket->socket);
    free(tun_socket);
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
    case TUN_SERVER_SOCKET:
        tun_ss_free(data.tun_ss);
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

int create_tun_ss_sh(socket_holder **sh) {

    int ret_val = 0;

    // Creating tun server socket.
    tun_server_socket *tun_ss;
    ret_val = create_tun_ss(&tun_ss);
    if (ret_val) return ret_val;

    socket_holder *holder;
    socket_data data;
    data.tun_ss = tun_ss;
    ret_val = create_sh(TUN_SERVER_SOCKET, data, &holder);
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

int map_is_tun_ss(socket_holder *holder) {
    return map_check_socket(holder, TUN_SERVER_SOCKET);
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

void uc_map_update(
    user_id id,
    std::map<int, udp_client_info*>& map,
    std::shared_mutex& mutex,
    udp_client_info *new_info
) {

    std::unique_lock lock(mutex);

    udp_client_info *info = map.at(id);
    if (info) {
        free(info);
        map.erase(id);
    }

    if (new_info) {
        map[id] = new_info;
    }
}

/* Probably a thread approach is be better approach since SSL_accept is I/O blocking.
*  When handling a new client there is no need to just create the client socket and return.
*  A dedicated process should handle the process of data exchange without relying on select in the main loop.
*  After a timeout or some error the client socket can be freed along with the thread.
*  This will simplify the whole logic.
*/
void handle_tcp_client_key_exchange(
    socket_t client_socket,
    struct sockaddr_storage client_address,
    socklen_t client_len,
    SSL_CTX *ctx,
    std::map<int, udp_client_info*>& map, 
    std::shared_mutex& mutex
) {

    SSL *ssl;
    if (ssl_utils::bind_ssl(ctx, client_socket, &ssl) == -1) {
        log_vpn_server_error(-1);
    }

    ssl_utils::log_ssl_cipher(ssl, client_address, client_len);

    client_credentials credentials;
    memset(&credentials, 0, sizeof(credentials));

    int size = sizeof(credentials.data);
    int read_error = ssl_utils::read(ssl, credentials.data, size);
    if (read_error) {
        log_vpn_server_error(UNEXPECTED_DISCONNECT);
        return;
    }

    int reading_credentials = 1;
    char *usr_p = credentials.username;
    char *pwd_p = credentials.password;

    for (int i = 0; i < size; ++i) {
        
        char bdata = credentials.data[i];
        
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

    /* DogeVPN requires a minimum length of bytes for the password.
    *  If the minimum length is not respected, than the database does not even gets accessed.
    */
    int pwd_len = strlen(credentials.password);
    if (pwd_len < MINIMUM_PWD_LEN) {
        log_vpn_server_error(PWD_TOO_SHORT);
        ssl_utils::free_ssl(ssl);
        return;
    }

    /* The user id is an important property for communicating over UDP.
    *  Once the id is fetched, it must be saved in memory.
    *  This is needed since the pakcet should be enrcypted and decrypted with the correct key.
    */
    user_id db_user_id = 42; // TODO
    char id_buf[ID_LEN];
    memset(id_buf, 0, ID_LEN);
    sprintf(id_buf, "%d", db_user_id);

    /* Generating a key by using the OpenSSL library.
    *  It will be shared with the client to communicate over UDP.
    */
    unsigned char rand_buf[KEY_LEN];
    memset(rand_buf, 0, KEY_LEN);
    int rand_value = RAND_bytes(rand_buf, KEY_LEN);
    if (rand_value != 1) {
        log_vpn_server_error(rand_value == -1 ? RAND_NOT_SUPPORTED : RAND_FAILURE);
        ssl_utils::free_ssl(ssl);
        return;
    }

    /* Composing the final message.
    *  It has the following form:
    *   - The first part is the key that will be used to encrypt and decrypt the data over UDP
    *   - There is a separator in the middle
    *   - The last part is the user id that it will be later on used to fetch the key that must be used
    */
    char message[MAX_KEY_MESSAGE_LEN];
    memset(message, 0, MAX_KEY_MESSAGE_LEN);
    char *msg_p = message;

    /* Copying the key.
    *  It will be the first part of the message (256 bit).
    */
    for (int i = 0; i < KEY_LEN; ++i) {
        *msg_p = rand_buf[i];
        msg_p++;
    }

    /* The separator within the message.
    *  After it the user id will be present.
    */
    *msg_p = MESSAGE_SEPARATOR;
    msg_p++;

    /* Adding the final part of the message that is the user id.
    *  It will be used to retrieve teh correct symmetric key for the UDP client.
    */
    char *id_p = id_buf;
    while(*id_p) {
        *msg_p = *id_p;
        msg_p++;
        id_p++;
    }

    udp_client_info *info = (udp_client_info*) malloc(sizeof(udp_client_info));
    if (!info) {
        log_vpn_server_error(OUT_OF_MEMORY);
        ssl_utils::free_ssl(ssl);
        return;
    }

    /* Updating the info map.
    *  Mutex is needed to protect shared memory.
    */
    uc_map_update(db_user_id, map, mutex, info);

    /* Errors can be different.
    *  A more resilient approach would be call SSL_get_error() to find out if it's retryable.
    */
    if (SSL_write(ssl, message, strlen(message)) <= 0) {

        log_vpn_server_error(SSL_WRITE_ERROR);

        uc_map_update(db_user_id, map, mutex, NULL);
        ssl_utils::free_ssl(ssl);
        return;
    }

    /* After the key has been exchanged the TCP connection gets closed.
    *  A better approach would be to keep the connection alive and use it to perform specific operations:
    *   - For example establish a new key after a while
    *   - Release UDP resources before the TCP connection goes away
    */
    ssl_utils::free_ssl(ssl);
}

void map_uc_free(std::map<int, udp_client_info*>& map, std::shared_mutex& mutex) {
    std::unique_lock lock(mutex);
    for (auto iter = map.begin(); iter != map.end(); ++iter) free(iter->second);
    map.clear();
}

/* Assumption ...
*/
int map_uc_extract_key(user_id id, std::map<int, udp_client_info*>& map, std::shared_mutex& mutex, char *key_buffer) {

    std::unique_lock lock(mutex);

    int ret_val = 0;
    udp_client_info *info = map.at(id);

    if (info == NULL) {
        ret_val = USER_IS_NOT_PRESENT;
        return ret_val;
    }

    memcpy(key_buffer, info->key, KEY_LEN);
    return ret_val;
}

/* This function deals with extracting the information. 
*  DogeVPN requires the payload to respect the following format:
*   1.  First part of the payload is the original encrypted packet.
*       The length is variable.
*   2.  After the payload there is the hash of the message signed with the exchanged key.
*       The main reason to exchange the hashed messsage is:
*           - Avoiding that the user id leak allow everyone to send non-sense packet.
*   3.  After the hashed part we have the IV
*   4.  Then we have the user id:
*           - This is needed to decrypt the message with correct key
*/
int extract_vpn_client_packet_data(const packet *from, vpn_client_packet_data *ret_data) {

    int ret_val = 0;
    int current_index = from->length - 1;
    memset(ret_data, 0, sizeof(vpn_client_packet_data));

    int j = 0;
    while (current_index >= 0) {

        char bdata = from->message[current_index--];

        /* Id has a specific length.
        *  When dealing with longer id, an error is returned.
        */
        if (j == ID_LEN && bdata != MESSAGE_SEPARATOR) {
            ret_val = INVALID_CLIENT_ID;
            return ret_val;
        }
        
        if (bdata == MESSAGE_SEPARATOR) {

            /* The user id is the last part of the message after the IV vector.
            *  After encountering it the user id processing must stop.  
            */
            break;
        } if (!isdigit(bdata)) {

            /* An user id contains only digits.
            *  When a different character is encountered an error value is returned.
            */
            ret_val = INVALID_CLIENT_ID;
            return ret_val;
        } else {

            ret_data->user_id[j++] = bdata;
        }

    }

    /* Sanity check.
    *  Id must not be empty.
    */
    if (j == 0) {
        ret_val = INVALID_CLIENT_ID;
        return ret_val;
    }

    /* Id has been read in reverse.
    *  In order to extract it correctly, a reverse operation is applied. 
    */
    utils::reverse_string((char *) ret_data->user_id, j);

    // IV extraction.
    if (utils::read_reverse(
        ret_data->iv,
        from->message,
        IV_LEN,
        from->length,
        &current_index,
        true
    ) == -1) return INVALID_IV;

    // Hash extraction.
    if (utils::read_reverse(
        ret_data->hash,
        from->message,
        SHA_256_BYTES,
        from->length,
        &current_index,
        true
    ) == -1) return INVALID_HASH;

    // Message extraction.
    size_t packet_length = utils::read_reverse(
        ret_data->encrypted_packet.message,
        from->message,
        MAX_MESSAGE_BYTES,
        from->length,
        &current_index,
        false
    );

    if (packet_length == -1) return INVALID_MESSAGE;
    ret_data->encrypted_packet.length = packet_length;

    return ret_val;
}

/* Errors should be notified to the client peer.
*  This should be done by using the initial TCP connection. 
*  This version does not include any error notification.
*/
int handle_incoming_udp_packet(
    socket_t udp_socket, 
    std::map<int, udp_client_info*>& map, 
    std::shared_mutex& mutex, 
    packet *ret_packet
) {

    int ret_val = 0;
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);

    /* Using the theoretical limit of an UDP packet.
    *  Instead of setting the MSG_PEEK flag, on safe bet is made on how much data to allocate.
    */
    packet pkt;
    memset(&pkt, 0, sizeof(packet));
    pkt.length = recvfrom(
        udp_socket, pkt.message,
        sizeof(pkt.message), 0,
        (struct sockaddr *) &client_address, &client_len
    );

    /* The value of zero is not considered an error.
    *  A connection can be closed by the other peer.
    */
    if (pkt.length == 0) {
        printf("UDP connection closed by a peer.\n");
        return ret_val;
    }

    /* A negative value should never happen.
    *  In this case no actions are perfromed, just returning the error.
    */
    if (pkt.length < 0) {
        ret_val = UDP_READ_ERROR;
        return ret_val;
    }

    char address_buffer[128];
    char service_buffer[128];
    getnameinfo(
        (struct sockaddr*) &client_address, client_len,
        address_buffer, sizeof(address_buffer), 
        service_buffer, sizeof(service_buffer),
        NI_NUMERICHOST | NI_NUMERICSERV
    );

    printf("Received %ld bytes from %s:%s\n", pkt.length, address_buffer, service_buffer);

    /* Now the main logic of must happen:
    *   1. Extract the the packet
    *   2. Check the presence of the id within the shared map
    *   3. Get the connection info to verify some UDP connection property
    *   4. Decrypt the packet
    *   5. Forward it to the TUN interface
    *  There can be different scenarios for which packets must be rejected.
    */
    vpn_client_packet_data vpn_data;
    ret_val = extract_vpn_client_packet_data(&pkt, &vpn_data);
    if (ret_val) return ret_val;

    int id_num;
    sscanf((const char *) vpn_data.user_id, "%d", &id_num);
    user_id user_id = id_num;

    /* Extracting the key .
    *  Write info about mutex...
    */
    char key[KEY_LEN];
    ret_val = map_uc_extract_key(user_id, map, mutex, key);
    if (ret_val) return ret_val;

    encryption_data enc_data;
    memcpy(enc_data.key, key, KEY_LEN);
    memcpy(enc_data.iv, vpn_data.iv, IV_LEN);

    packet decrypted_message = encryption::decrypt(vpn_data.encrypted_packet, enc_data);
    *ret_packet = decrypted_message;

    // With the encrypted packet we must verify the hash.
    ret_val = encryption::hash_verify(decrypted_message, vpn_data.hash, enc_data);

    return ret_val;
}

int start_doge_vpn() {

    int ret_val = 0;
    socket_t max_socket = 0;

    SSL_CTX *ctx = NULL;
    socket_holder *tss_holder = NULL;
    socket_holder *uss_holder = NULL;
    socket_holder *tun_ss_holder = NULL;

    std::map<socket_t, socket_holder*> sh_map;
    std::map<user_id, udp_client_info*> uc_map;
    std::shared_mutex uc_map_mutex;

    fd_set master;

    // Initialization of the tun server socket.
    //ret_val = create_tun_ss_sh(&tun_ss_holder);
    //if (ret_val) goto error_handler;
    //map_set_max_add(sh_map, &master, tun_ss_holder, &max_socket);

    // SSL initialization.
    ret_val = ssl_utils::init_ssl(&ctx, true, "certs/cert.pem", "certs/key.pem");
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

        for (socket_t socket = 0; socket <= max_socket; ++socket) {

           if (FD_ISSET(socket, &reads)) {

                if (socket == extract_socket(tss_holder)) {

                    /* The TCP socket is ready to accept a new client.
                    *  By calling accept, a new client socket will be created.
                    *  Calling accept won't block the main thread since a call to select was made.
                    */
                    struct sockaddr_storage client_address;
                    socklen_t client_len = sizeof(client_address);
                    socket_t client_socket = accept(socket, (struct sockaddr*) &client_address, &client_len);

                    if (socket_utils::invalid_socket(client_socket)) {

                        /* Calling accept failed.
                        *  This could fail when the connections reach the maximum allowed number.
                        */
                        log_vpn_server_error(TCP_ACCEPT_ERROR);
                    } else {

                        /* Why do we need to start a new thread when handling a new client?
                        *  SSL operations may block on a slow client.
                        *  Instead of blocking the entire server we may want to block only one therad.
                        *  This thread is in charge of establish a TLS connection and exchange a key for UDP.
                        */
                        std::thread th(
                            handle_tcp_client_key_exchange, 
                            client_socket,
                            client_address,
                            client_len,
                            ctx, 
                            std::ref(uc_map), 
                            std::ref(uc_map_mutex)
                        );

                        th.detach();
                    }
                } else if (socket == extract_socket(uss_holder)) {

                    packet received_packet;
                    int some_error = handle_incoming_udp_packet(socket, uc_map, uc_map_mutex, &received_packet);

                    if (some_error) {
                        log_vpn_server_error(some_error);
                    } else {

                    }
                } else {

                    // if (socket == extract_socket(tun_ss_holder))

                    /* This section should handle specific client packets by using the TCP connection.
                    *  The TCP connection should be kept in order to perform reliable actions.
                    */
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
    map_uc_free(uc_map, uc_map_mutex);

    return ret_val;
}

void test_enc_dec() {

    encryption_data ed;

    for (int i = 0; i < KEY_LEN; ++i) ed.key[i] = 42;
    for (int i = 0; i < IV_LEN; ++i) ed.iv[i] = 10;

    packet pkt;
    pkt.message[0] = '1';
    pkt.message[1] = '2';
    pkt.length = 2;

    packet enc_pkt;
    memset(&enc_pkt, 0, sizeof(packet));
    encryption::encrypt(pkt, ed, &enc_pkt);

    printf("Encrypted data should be %d bytes long and it is of length %ld\n", 16, enc_pkt.length);

    packet dec_pkt;
    memset(&dec_pkt, 0, sizeof(packet));
    dec_pkt = encryption::decrypt(enc_pkt, ed);
    printf("Decrypted data should be %d bytes long and it is of length %ld\n", 2, dec_pkt.length);
}

void test_extract() {

    packet pkt;
    memset(&pkt, 0, sizeof(packet));

    int start = 0;

    for (int i = 0; i < 16; ++i) pkt.message[start++] = 'm';
    for (int i = 0; i < SHA_256_BYTES; ++i) pkt.message[start++] = 'h';
    for (int i = 0; i < IV_LEN; ++i) pkt.message[start++] = 'i';
    pkt.message[start++] = '.';
    for (int i = 0; i < 8; ++i) pkt.message[start++] = '1';
    pkt.length = strlen((const char *)&pkt.message);

    vpn_client_packet_data data;
    extract_vpn_client_packet_data(&pkt, &data);

    int all_equals = 
        strncmp((const char *) data.encrypted_packet.message, "mmmmmmmmmmmmmmmm", 16) +
        strncmp((const char *) data.user_id, "11111111", 8) +
        strncmp((const char *) data.iv, "iiiiiiiiiiiiiiii", 16) +
        strncmp((const char *) data.hash, "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh", 32);

    printf("Sum should be %d and it is %d\n", 0, all_equals);
    printf("Length should be %d and it is %ld\n", 16, data.encrypted_packet.length);
}

void test_enc_packet() {

    encryption_data ed;
    for (int i = 0; i < KEY_LEN; ++i) ed.key[i] = 42;
    for (int i = 0; i < IV_LEN; ++i) ed.iv[i] = 'l';

    char *message = "Hello";
    packet enc_packet;
    encryption::create_encrypted_packet(message, strlen(message), ed, &enc_packet);

    printf("Length should be %d and it is %ld\n", 32, enc_packet.length);
}

void test_suite() {

    test_enc_dec();
    test_extract();
    test_enc_packet();
}

int main() {

    test_suite();
    //return 0;
	return start_doge_vpn();
}
