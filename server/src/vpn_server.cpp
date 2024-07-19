#include "standards.h"
#include "defines.h"
#include "data_structures.h"
#include "encryption.h"
#include "utils.h"
#include "ssl_utils.h"
#include "socket_utils.h"
#include "client_credentials_utils.h"
#include "udp_client_info_utils.h"
#include "vpn_data_utils.h"
#include "mongo.hpp"

socket_utils::socket_t extract_socket(socket_holder *holder) {

    socket_type type = holder->type;
    switch (type) {
    case TCP_CLIENT_SOCKET:
        return (holder->data).tcs->socket;
    case TCP_SERVER_SOCKET:
        return (holder->data).tss->socket;
    case UDP_SERVER_SOCKET:
        return (holder->data).uss->socket;
    default:
        exit(1);
    }

    return -1;
}

void tcs_free(tcp_client_socket *tcs) {

    // Sanity check.
    if (tcs == NULL) return;

    ssl_utils::free_ssl(tcs->ssl, NULL);
    free(tcs);
}

int create_tss(
    char const *host, 
    char const *port,
    tcp_server_socket **tcp_socket
) {

    int ret_val = 0;
    
    socket_utils::socket_t socket;
    if (socket_utils::bind_tcp_server_socket(host, port, &socket) == -1) {
        utils::print_error("create_tss: cannot create TCP server socket\n");
        return -1;
    }

    tcp_server_socket *ret_data = (tcp_server_socket *) malloc(sizeof(tcp_server_socket));
    if (!ret_data) {
        utils::print_error("create_tss: cannot create TCP server socket data\n");
        socket_utils::close_socket(socket);
        return -1;
    }

    // Setting up the tcp server socket.
    socket_utils::log_start_server(true, host, port);
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

    /* A UDP socket does not need to set itself to a listen state.
    *  Just up to bind. 
    */
    socket_utils::socket_t socket;
    if (socket_utils::bind_udp_server_socket(host, port, &socket) == -1) {
        utils::print_error("create_uss: cannot create UDP server socket\n");
        return -1;
    }

    udp_server_socket *uss = (udp_server_socket *) malloc(sizeof(udp_server_socket));
    if (!uss) {
        utils::print_error("create_uss: cannot create UDP server socket data\n");
        socket_utils::close_socket(socket);
        return -1;
    }

    // Setting up the udp server socket.
    socket_utils::log_start_server(false, host, port);
    uss->socket = socket;
    *udp_socket = uss;

    return 0;
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
    default:
        exit(1);
    }
}

int create_sh(socket_type type, socket_data data, socket_holder **sh) {

    int ret_val = 0;

    socket_holder *holder = (socket_holder *) malloc(sizeof(socket_holder));
    if (!holder) {
        socket_data_free(type, data);
        return -1;
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
    socket_holder **sh
) {

    int ret_val = 0;

    // Creating tcp server socket.
    tcp_server_socket *tss;
    ret_val = create_tss(host, port, &tss);
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

void map_set_max_add(
    std::map<socket_utils::socket_t, socket_holder*>& map, 
    fd_set *set,
    socket_holder *holder,
    socket_utils::socket_t *max_socket
) {

    // Assuming extract_socket does not retun -1.
    socket_utils::socket_t socket = extract_socket(holder);

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
    std::map<socket_utils::socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_utils::socket_t *max_socket
) {

    for (auto iter = map.begin(); iter != map.end(); ++iter) {

        // Getting key and value.
        socket_utils::socket_t socket = iter->first;
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
    std::map<socket_utils::socket_t, socket_holder*>& map, 
    fd_set *master_set,
    socket_utils::socket_t *max_socket
) {

    int ret_val = 0;
    tcp_client_socket *tcs = holder->data.tcs;
    socket_utils::socket_t socket = tcs->socket;

    // Updating the max_socket value.
    if (socket == *max_socket) {

        // This is possible since the because the map in C++ is in increasing order of keys by default.
        auto pair = ++map.rbegin();
        socket_utils::socket_t max_socket_from_map = pair->first;
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

void uc_map_update(
    user_id id,
    std::map<int, udp_client_info*>& map,
    std::shared_mutex& mutex,
    udp_client_info *new_info
) {

    /* Updating the map.
    *  Mutex is needed to protect shared memory.
    */
    std::unique_lock lock(mutex);

    if (map.count(id)) {

        udp_client_info *info = map.at(id);
        if (info != NULL) free(info);
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
    socket_utils::socket_t client_socket,
    struct sockaddr_storage client_address,
    socklen_t client_len,
    SSL_CTX *ctx,
    std::map<int, udp_client_info*>& map, 
    std::shared_mutex& mutex
) {

    SSL *ssl;
    if (ssl_utils::bind_ssl(ctx, client_socket, &ssl, true) == -1) {
        utils::print_error("handle_tcp_client_key_exchange: TLS communication cannot start between client and server\n");
        return;
    }
    
    ssl_utils::log_ssl_cipher(ssl, client_address, client_len);

    char credentials_buffer[512];
    int bytes_read = ssl_utils::read(ssl, credentials_buffer, sizeof(credentials_buffer));
    if (bytes_read == -1) {
        utils::print_error("handle_tcp_client_key_exchange: Client closed connection and credentials cannot be verified\n");
        return;
    }

     client_credentials_utils::client_credentials credentials;
    if (client_credentials_utils::initialize(credentials_buffer, bytes_read, &credentials) == -1) {
        utils::print_error("handle_tcp_client_key_exchange: client credentials cannot be initialized\n");
        ssl_utils::free_ssl(ssl, NULL);
        return;
    }

    utils::println_sep(0);
    client_credentials_utils::log_client_credentials(&credentials);

    /* The user id is an important property for communicating over UDP.
    *  Once the id is fetched, it must be saved in memory.
    *  This is needed since the pakcet should be enrcypted and decrypted with the correct key.
    */
    user_id db_user_id = 42; // TODO
    unsigned char id_buf[64];
    memset(id_buf, 0, 64);
    sprintf((char *) id_buf, "%d", db_user_id);

    unsigned char rand_buf[32];
    if (ssl_utils::generate_rand_32(rand_buf) == -1) {
        utils::print_error("handle_tcp_client_key_exchange: random bytes cannot be generated");
        ssl_utils::free_ssl(ssl, NULL);
        return;
    }

    // TODO check error.
    char message[256];
    utils::concat_with_separator(
        (const char *) rand_buf, sizeof(rand_buf), 
        (const char *) id_buf, sizeof(id_buf), 
        message, sizeof(message), 
        '.'
    );

    size_t message_length = sizeof(rand_buf) + strlen((const char *) id_buf) + 1;
    utils::println_sep(0);
    utils::print_bytes("Generating message for the client", message, message_length, 5);

    udp_client_info *info;
    if (udp_client_info_utils::init((const char *) rand_buf, sizeof(rand_buf), &info) == -1) {
        utils::print_error("handle_tcp_client_key_exchange: client info cannot be saved\n");
        ssl_utils::free_ssl(ssl, NULL);
        return;
    }

    uc_map_update(db_user_id, map, mutex, info);

    if (ssl_utils::write(ssl, message, message_length) == -1) {
        utils::print_error("handle_tcp_client_key_exchange: key cannot be shared with the client\n");
        uc_map_update(db_user_id, map, mutex, NULL);
        return;
    }

    /* After the key has been exchanged the TCP connection gets closed.
    *  A better approach would be to keep the connection alive and use it to perform specific operations:
    *   - For example establish a new key after a while
    *   - Release UDP resources before the TCP connection goes away
    */
    ssl_utils::free_ssl(ssl, NULL);
}

void map_uc_free(std::map<int, udp_client_info*>& map, std::shared_mutex& mutex) {
    std::unique_lock lock(mutex);
    for (auto iter = map.begin(); iter != map.end(); ++iter) free(iter->second);
    map.clear();
}

/* Functions that deals with shared data must always return new data:
*   - The data type udp_client_info is not returned directly since it can be accessed and deleted by another thread
*   - In order to avoid race condition, after taking the mutex, a copy of the key is returned
*/
int map_uc_extract_key(user_id id, std::map<int, udp_client_info*>& map, std::shared_mutex& mutex, char *key_buffer) {

    std::unique_lock lock(mutex);

    if (map.count(id)) {

        udp_client_info *info = map.at(id); 
        memcpy(key_buffer, info->key, encryption::MAX_KEY_SIZE);
        return 0;
    } else {

        utils::print_error("map_uc_extract_key: invalid id\n");
        return -1;
    }
}

int extract_vpn_client_packet_data(
    const encryption::packet *from,
    vpn_data_utils::vpn_client_packet_data *ret_data
) {

    if (vpn_data_utils::parse_packet(from, ret_data) == -1) {
        utils::print_error("extract_vpn_client_packet_data: packet from client is malformed and data cannot be extracted\n");
        return -1;
    }

    vpn_data_utils::log_vpn_client_packet_data(ret_data);
    return 0;
}

/* Errors should be notified to the client peer.
*  This should be done by using the initial TCP connection. 
*  This version does not include any error notification.
*/
int handle_incoming_udp_packet(
    socket_utils::socket_t udp_socket, 
    std::map<int, udp_client_info*>& map, 
    std::shared_mutex& mutex, 
    encryption::packet *ret_packet
) {

    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);

    /* Using the theoretical limit of an UDP packet.
    *  Instead of setting the MSG_PEEK flag, on safe bet is made on how much data to allocate.
    */
    encryption::packet pkt;
    memset(&pkt, 0, sizeof(encryption::packet));
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
        return 0;
    }

    /* A negative value should never happen.
    *  In this case no actions are performed, just returning the error.
    */
    if (pkt.length < 0) {
        utils::print_error("handle_incoming_udp_packet: invalid packet length\n");
        return -1;
    }

    socket_utils::log_client_address(client_address, client_len);

    /* Now the main logic of must happen:
    *   1. Extract the the packet
    *   2. Check the presence of the id within the shared map
    *   3. Get the connection info to verify some UDP connection property
    *   4. Decrypt the packet
    *   5. Forward it to the TUN interface
    *  There can be different scenarios for which packets must be rejected.
    */
    vpn_data_utils::vpn_client_packet_data vpn_data;
    if (extract_vpn_client_packet_data(&pkt, &vpn_data) == -1) {
        utils::print_error("handle_incoming_udp_packet: vpn data cannot be extracted\n");
        return -1;
    }

    int id_num;
    sscanf((const char *) vpn_data.user_id, "%d", &id_num);
    user_id user_id = id_num;

    char key[encryption::MAX_KEY_SIZE];
    if (map_uc_extract_key(user_id, map, mutex, key) == -1) return -1;

    encryption::encryption_data enc_data;
    memcpy(enc_data.key, key, encryption::MAX_KEY_SIZE);
    memcpy(enc_data.iv, vpn_data.iv, encryption::MAX_IV_SIZE);

    encryption::packet decrypted_message = encryption::decrypt(vpn_data.encrypted_packet, enc_data);
    *ret_packet = decrypted_message;

    // With the encrypted packet we must verify the hash.
    if (encryption::hash_verify(decrypted_message, vpn_data.hash, enc_data) == -1) {
        utils::print_error("handle_incoming_udp_packet: wrong hash detected\n");
        return -1;
    }

    return 0;
}

int start_doge_vpn() {

    int ret_val = 0;
    socket_utils::socket_t max_socket = 0;

    SSL_CTX *ctx = NULL;
    socket_holder *tss_holder = NULL;
    socket_holder *uss_holder = NULL;
    socket_holder *tun_ss_holder = NULL;

    std::map<socket_utils::socket_t, socket_holder*> sh_map;
    std::map<user_id, udp_client_info*> uc_map;
    std::shared_mutex uc_map_mutex;

    fd_set master;

    // SSL initialization.
    ret_val = ssl_utils::init_ssl(&ctx, true, "certs/cert.pem", "certs/key.pem");
    if (ret_val) goto error_handler;

    // Initialization of master set for further selects.
    FD_ZERO(&master);

    // Initialization of the tcp server socket.
    ret_val = create_tss_sh("0.0.0.0", "8080", &tss_holder);
    if (ret_val) goto error_handler;
    map_set_max_add(sh_map, &master, tss_holder, &max_socket);

    // Initialization of the udp server socket.
    ret_val = create_uss_sh("0.0.0.0", "8080", &uss_holder);
    if (ret_val) goto error_handler;
    map_set_max_add(sh_map, &master, uss_holder, &max_socket);

    while(true) {

        // Copy of master, otherwise we would lose its data.
        fd_set reads;
        reads = master;

        if (select(max_socket + 1, &reads, 0, 0, 0) < 0) goto error_handler;

        for (socket_utils::socket_t socket = 0; socket <= max_socket; ++socket) {

           if (FD_ISSET(socket, &reads)) {

                if (socket == extract_socket(tss_holder)) {

                    /* The TCP socket is ready to accept a new client.
                    *  By calling accept, a new client socket will be created.
                    *  Calling accept won't block the main thread since a call to select was made.
                    */
                    struct sockaddr_storage client_address;
                    socklen_t client_len = sizeof(client_address);
                    socket_utils::socket_t client_socket = accept(socket, (struct sockaddr*) &client_address, &client_len);

                    if (socket_utils::invalid_socket(client_socket)) {

                        /* Calling accept failed.
                        *  This could fail when the connections reach the maximum allowed number.
                        */
                        utils::print_error("start_doge_vpn: cannot accept new client\n");
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

                    encryption::packet received_packet;
                    if (handle_incoming_udp_packet(socket, uc_map, uc_map_mutex, &received_packet) == -1) {
                        utils::print_error("start_doge_vpn: udp packet of client cannot be verified\n");
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
    utils::print_error("start_doge_vpn: fatal error, switching off the server");

    // Cleaning up resources.
    ssl_context_free(ctx);
    map_set_max_free(sh_map, &master, &max_socket);
    map_uc_free(uc_map, uc_map_mutex);

    return -1;
}

int main() {
	return start_doge_vpn();
}
