#include "holder.h"

namespace holder {

    int init_tcp_server_holder(char const *host, char const *port, socket_holder *holder) {
        
        socket_utils::socket_t socket;
        if (socket_utils::bind_tcp_server_socket(host, port, &socket) == -1) {
            fprintf(stderr, "init_tcp_server_holder: cannot create TCP server socket\n");
            return -1;
        }

        holder->holder_type = socket_holder::SERVER_HOLDER;
        holder->s_holder = {true, socket};
        socket_utils::log_start_server(true, host, port);

        return 0;
    }

    int init_client_holder(
        tun_utils::ip_pool_t *pool,
        socket_utils::socket_t client_socket,
        struct sockaddr_storage client_address,
        socklen_t client_len,
        SSL_CTX *ctx,
        socket_holder *holder
    ) {

        SSL *ssl;
        if (ssl_utils::bind_ssl(ctx, client_socket, &ssl, true) == -1) {
            fprintf(stderr, "init_tcp_client_holder: TLS communication cannot start between client and server\n");
            return -1;
        }

        ssl_utils::log_ssl_cipher(ssl, client_address, client_len);

        /* Reading credentials from client.
        *  If ssl_utils::read fails the already created TLS data gets autmatically erased.
        *  No need to call ssl_utils::free_ssl.
        */
        char credentials_buffer[SIZE_512];
        int bytes_read = ssl_utils::read(ssl, credentials_buffer, sizeof(credentials_buffer));
        if (bytes_read == -1) {
            fprintf(stderr, "init_tcp_client_holder: client closed connection and credentials cannot be verified\n");
            return -1;
        }

        client_credentials_utils::client_credentials credentials;
        if (client_credentials_utils::initialize(credentials_buffer, bytes_read, &credentials) == -1) {
            fprintf(stderr, "init_tcp_client_holder: client credentials cannot be initialized\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        client_credentials_utils::log_client_credentials(&credentials);

        /* The user id is an important property for communicating over UDP.
        *  Once the id is fetched, it must be saved in memory.
        *  This is needed since the pakcet should be enrcypted and decrypted with the correct key.
        */
        unsigned int db_user_id = 42;
        char id_buf[SIZE_32];
        memset(id_buf, 0, sizeof(id_buf));
        sprintf(id_buf, "%d", db_user_id); // Replace with mongo check.

        /* A symmetric key must be generated securely.
        *  The SSL libarary is used in order to properly delegate such difficutl generation.
        */
        unsigned char rand_buf[SIZE_32];
        if (ssl_utils::generate_rand_32(rand_buf) == -1) {
            fprintf(stderr, "init_tcp_client_holder: random bytes cannot be generated\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        /* In order to preoperly communicate with the correct client a TUN ip must be assigned.
        *  This ip must uniquely identify the client.
        *  When the packet gets sent back from a private host, the correct key and the correct client ip must be selected.
        */
        char tun_ip[SIZE_32];
        unsigned int client_tun_ip_id;
        if (tun_utils::next(pool, tun_ip, sizeof(tun_ip), &client_tun_ip_id) == NULL) {
            fprintf(stderr, "init_tcp_client_holder: unavailable ip for client\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        /* Composing the first message for the client. */
        int start = 0;
        char message[SIZE_512];
        bzero(message, sizeof(message));

        for (size_t i = 0; i < sizeof(rand_buf); i++) message[start++] = rand_buf[i];
        message[start++] = MESSAGE_SEPARATOR_POINT;

        char *ptr = id_buf;
        while (*ptr) {
            message[start++] = *ptr;
            ptr++;
        }

        message[start++] = MESSAGE_SEPARATOR_POINT;
        message[start++] = MESSAGE_SEPARATOR_OPEN;

        ptr = tun_ip;
        while (*ptr) {
            message[start++] = *ptr;
            ptr++;
        }

        message[start++] = MESSAGE_SEPARATOR_CLOSE;

        size_t message_size = 
            sizeof(rand_buf) +  /* Size of the key */
            1 +                 /* Point separator */
            strlen(id_buf) +    /* Session id size */
            1 +                 /* Point separator */
            1 +                 /* Open round bracket */
            strlen(tun_ip) +    /* TUN ip size */
            1;                  /* Closed open bracket */

        /* Sending the message to the client securely under a TLS tunnel. */
        if (ssl_utils::write(ssl, message, message_size) == -1) {
            fprintf(stderr, "init_tcp_client_holder: first wrote failed between client and server\n");
            return -1;
        }

        /* Printing message bytes for logging purposes. */
        printf("Client message generated\n");

        for (size_t i = 0; i < sizeof(message); ++i) {

            if (!message[i]) break;
            printf("%02X", (unsigned char) message[i]);

            if (i != 0) {
                if (i % 8 == 0) printf("\n");
                else printf("::");
            }
        }

        /* After the operations that must be always performed, holder can be populated. */
        holder::client_holder client_holder;

        client_holder.session_id = db_user_id;
        client_holder.client_tun_ip_id = client_tun_ip_id;
        memcpy(client_holder.symmetric_key, rand_buf, sizeof(rand_buf));
        memcpy(client_holder.client_tun_ip.ip, tun_ip, sizeof(tun_ip));

        client_holder.socket = client_socket;
        client_holder.tcp_socklen = client_len;
        client_holder.tcp_address = client_address;

        client_holder.ssl = ssl;

        holder->holder_type = socket_holder::CLIENT_HOLDER;
        holder->c_holder = client_holder;

        return 0;
    }

    int init_udp_server_holder(char const *host, char const *port, socket_holder *holder) {

        socket_utils::socket_t socket;
        if (socket_utils::bind_udp_server_socket(host, port, &socket) == -1) {
            fprintf(stderr, "init_udp_server_holder: cannot create UDP server socket\n");
            return -1;
        }

        holder->holder_type = socket_holder::SERVER_HOLDER;
        holder->s_holder = {false, socket};
        socket_utils::log_start_server(false, host, port);

        return 0;
    }

    socket_utils::socket_t extract_socket(const socket_holder *wrapper) {

        if (wrapper == NULL) return socket_utils::invalid_socket_value;

        switch (wrapper->holder_type) {
            case socket_holder::SERVER_HOLDER:
                return (wrapper->s_holder).socket;
            case socket_holder::CLIENT_HOLDER:
                return (wrapper->c_holder).socket;
            default:
                return socket_utils::invalid_socket_value;
        }
    }

    void save_client_holder(client_register *c_register, client_holder holder) {

        std::unique_lock lock(c_register->mutex);

        c_register->session_per_holder.insert({holder.session_id, holder});
        c_register->tun_ip_per_session.insert({holder.client_tun_ip, holder.session_id});
    }

    void delete_client_holder(client_register *c_register, tun_utils::ip_pool_t *pool, client_holder holder) {

        {
            std::unique_lock lock(c_register->mutex);

            unsigned int session_id = holder.session_id;
            tun_ip ip = holder.client_tun_ip;
            
            if (c_register->session_per_holder.count(session_id) != 0) {
                c_register->session_per_holder.erase(session_id);
            }

            if (c_register->tun_ip_per_session.count(ip) != 0) {
                c_register->tun_ip_per_session.erase(ip);
            }

        }

        tun_utils::erase(pool, holder.client_tun_ip_id);
        ssl_utils::free_ssl(holder.ssl, NULL);
    }

    int extract_client_key(
        client_register *c_register,
        unsigned int session_id,
        unsigned char *symmetric_key
    ) {

        std::shared_lock lock(c_register->mutex);

        if (c_register->session_per_holder.count(session_id) == 0) {
            return -1;
        }

        client_holder c_holder = c_register->session_per_holder.at(session_id);
        memcpy(symmetric_key, c_holder.symmetric_key, SIZE_32);

        return 0;
    }

    holder::socket_holder create_server_holder_or_abort(const char *ip, const char *port, bool is_tcp) {

        holder::socket_holder holder;

        int result = is_tcp ? 
            holder::init_tcp_server_holder(ip, port, &holder) :
            holder::init_udp_server_holder(ip, port, &holder);

        if (result == -1) {
            fprintf(stderr, "create_server_holder_or_abort: %s server cannot start\n", is_tcp ? "tcp" : "udp");
            exit(EXIT_FAILURE);
        }

        return holder;
    }
}