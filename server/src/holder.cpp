#include "holder.h"

namespace holder {

    tun_ip extract_tun_ip_or_abort(client_register *c_register, unsigned int session_id) {

        std::shared_lock lock(c_register->mutex);

        if (c_register->session_per_holder.count(session_id) == 0) {
            fprintf(stderr, "extract_tun_ip: ip cannot be extracted\n");
            exit(EXIT_FAILURE);
        }

        return c_register->session_per_holder.at(session_id).client_tun_ip;
    }

    bool tun_ip::operator==(const tun_ip &o) const {
        return strncmp(ip, o.ip, SIZE_32) == 0 ? true : false;
    }

    bool tun_ip::operator<(const tun_ip &o) const {
        return strncmp(ip, o.ip, SIZE_32) < 0 ? true : false;
    }

    client_register::client_register(unsigned char third_octet) {
        tun_utils::configure_private_class_c_pool(third_octet, &pool);
    }

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

    int update_register(client_register *c_register, client_holder holder, bool saving, bool free_old_ssl) {

        std::unique_lock lock(c_register->mutex);

        unsigned int session_id = holder.session_id;

        /* In order to avoid dealing with wrong behaviour (i.e. old client have not been properly released),
        *  every time a new client gets registered, a delete pass gets executed.
        *  This is done for both maps.
        */
        if (c_register->session_per_holder.count(session_id) != 0) {

            client_holder old_holder = c_register->session_per_holder.at(session_id);
            tun_ip old_client_tun_ip = old_holder.client_tun_ip;

            tun_utils::insert(&(c_register->pool), old_holder.client_tun_ip_id);

            if (c_register->tun_ip_per_session.count(old_client_tun_ip) != 0) {
                c_register->tun_ip_per_session.erase(old_client_tun_ip);
            }

            if (free_old_ssl) {
                ssl_utils::free_ssl(old_holder.ssl, NULL);
            }

            c_register->session_per_holder.erase(session_id);
        }

        if (saving) {

            /* In order to preoperly communicate with the correct client a TUN ip must be assigned,
            *  and this ip must uniquely identify the client. 
            *  When the packet gets sent back from a private host, 
            *  the correct key and the correct client ip must be selected.
            */
            char tun_ip[SIZE_32];
            unsigned int client_tun_ip_id;
            if (tun_utils::next(&(c_register->pool), tun_ip, sizeof(tun_ip), &client_tun_ip_id) == NULL) {
                fprintf(stderr, "init_tcp_client_holder: unavailable ip for client\n");
                return -1;
            }

            holder.client_tun_ip_id = client_tun_ip_id;
            memcpy(holder.client_tun_ip.ip, tun_ip, sizeof(tun_ip));

            c_register->session_per_holder.insert({session_id, holder});
            c_register->tun_ip_per_session.insert({holder.client_tun_ip, session_id});
        }

        return 0;
    }

    void save_client_holder(client_register *c_register, client_holder holder) {
        update_register(c_register, holder, true, true);
    }

    void delete_client_holder(client_register *c_register, client_holder holder) {
        update_register(c_register, holder, false, true);
    }

    std::optional<vpn_data_utils::credentials> create_credentials(const char *data, size_t num) {

        std::optional<vpn_data_utils::credentials> opt;

        try {
            vpn_data_utils::credentials credentials(data, num);
            opt = credentials;
        } catch(const std::exception& e) {
            std::cerr << e.what() << '\n';
            opt = {};
        }

        return opt;
    }

    bool client_register::register_client_holder(SSL_CTX *ctx, socket_utils::tcp_client_info *info) {

        client_holder holder;
        holder.tcp_info.socket = info->socket;
        holder.tcp_info.length = info->length;
        holder.tcp_info.address = info->address;

        SSL *ssl;
        if (ssl_utils::bind_ssl(ctx, info->socket, &ssl, true) == -1) {
            fprintf(stderr, "register_client_holder: TLS communication cannot start between client and server\n");
            return -1;
        }

        ssl_utils::log_ssl_cipher(ssl, info->address, info->length);
        holder.ssl = ssl;

        char credentials_buffer[SIZE_512];
        int bytes_read = ssl_utils::read(ssl, credentials_buffer, sizeof(credentials_buffer));
        if (bytes_read == -1) {
            fprintf(stderr, "register_client_holder: client closed connection and credentials cannot be verified\n");
            return -1;
        }

        std::optional<vpn_data_utils::credentials> credentials = create_credentials(credentials_buffer, bytes_read);
        if (!credentials.has_value()) {
            fprintf(stderr, "register_client_holder: client credentials cannot be initialized\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        credentials
            .value()
            .log_credentials_from_client_message();

        /* The user id is an important property for communicating over UDP.
        *  Once the id is fetched, it must be saved in memory.
        *  This is needed since the pakcet should be enrcypted and decrypted with the correct key.
        */
        unsigned int db_user_id = 42;
        char id_buf[SIZE_32];
        memset(id_buf, 0, sizeof(id_buf));
        sprintf(id_buf, "%d", db_user_id); // Replace with mongo check.

        holder.session_id = db_user_id;

        /* A symmetric key must be generated securely.
        *  The SSL libarary is used in order to properly delegate such difficutl generation.
        */
        unsigned char rand_buf[SIZE_32];
        if (ssl_utils::generate_rand_32(rand_buf) == -1) {
            fprintf(stderr, "register_client_holder: random bytes cannot be generated\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        memcpy(holder.symmetric_key, rand_buf, sizeof(rand_buf));
        
        /* Check error*/
        if (update_register(this, holder, true, true) == -1) {
            fprintf(stderr, "register_client_holder: random bytes cannot be generated\n");
            ssl_utils::free_ssl(ssl, NULL);
            return -1;
        }

        /* Composing the first message for the client. */
        int start = 0;
        char message[SIZE_512];
        bzero(message, sizeof(message));

        for (size_t i = 0; i < sizeof(rand_buf); i++) message[start++] = rand_buf[i];

        char *ptr = id_buf;
        while (*ptr) {
            message[start++] = *ptr;
            ptr++;
        }

        message[start++] = MESSAGE_SEPARATOR_POINT;

        tun_ip tun_ip = extract_tun_ip_or_abort(this, holder.session_id);
        ptr = tun_ip.ip;
        while (*ptr) {
            message[start++] = *ptr;
            ptr++;
        }

        size_t message_size = 
            sizeof(rand_buf) +  /* Size of the key */
            strlen(id_buf) +    /* Session id size */
            1 +                 /* Point separator */
            strlen(tun_ip.ip);  /* TUN ip size */

        /* Sending the message to the client securely under a TLS tunnel. */
        if (ssl_utils::write(ssl, message, message_size) == -1) {
            fprintf(stderr, "register_client_holder: first wrote failed between client and server\n");
            update_register(this, holder, false, false);
            return -1;
        }

        /* Printing message bytes for logging purposes. */
        printf("Client message generated\n");

        for (size_t i = 0; i < message_size; ++i) {

            if (i % 8 == 7 || i == message_size - 1) printf("%02X\n", (unsigned char) message[i]);
            else printf("%02X::", (unsigned char) message[i]);
        }

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
                return (wrapper->c_holder).tcp_info.socket;
            default:
                return socket_utils::invalid_socket_value;
        }
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