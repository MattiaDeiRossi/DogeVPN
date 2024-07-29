#ifndef HOLDER_H
#define HOLDER_H

#include <map>
#include <shared_mutex>
#include <mutex>
#include "socket_utils.h"
#include "ssl_utils.h"
#include "client_credentials_utils.h"
#include "tun_utils.h"

namespace holder {

    const size_t SIZE_512 = 512;
    const size_t SIZE_32 = 32;
    const char MESSAGE_SEPARATOR_POINT = '.';
    const char MESSAGE_SEPARATOR_OPEN = '(';
    const char MESSAGE_SEPARATOR_CLOSE = ')';

    struct tun_ip {
        char ip[SIZE_32];

        bool operator==(const tun_ip &o) const {
            return strncmp(ip, o.ip, SIZE_32) == 0 ? true : false;
        }

        bool operator<(const tun_ip &o)  const {
            return strncmp(ip, o.ip, SIZE_32) < 0 ? true : false;
        }
    };

    struct client_holder {

        /*
        */
        unsigned int session_id;
        unsigned int client_tun_ip_id;
        unsigned char symmetric_key[SIZE_32];
        tun_ip client_tun_ip;

        /*
        */
        socket_utils::socket_t socket;
        socklen_t tcp_socklen;
        struct sockaddr_storage tcp_address;

        /*
        */
        socklen_t udp_socklen;
        struct sockaddr_storage udp_address;

        /*
        */
        SSL *ssl;    
    };

    struct server_holder {
        bool is_tcp;
        socket_utils::socket_t socket;
    };
    
    struct socket_holder {

        enum {
            CLIENT_HOLDER,
            SERVER_HOLDER
        } holder_type;

        union {
            client_holder c_holder;
            server_holder s_holder;
        };
    };

    /* Register of current connected client.
    *  Whenever a client connects or disconnects, this should be properly updated.
    */
    struct client_register {

        std::map<unsigned int, client_holder> session_per_holder;
        std::map<tun_ip, unsigned int> tun_ip_per_session;
        
        /* This register must be pretected with mutex. */
        std::shared_mutex mutex;
    };

    int init_tcp_server_holder(char const *host, char const *port, socket_holder *holder);

    int init_client_holder(
        tun_utils::ip_pool_t *pool,
        socket_utils::socket_t client_socket,
        struct sockaddr_storage client_address,
        socklen_t client_len,
        SSL_CTX *ctx,
        socket_holder *holder
    );

    int init_udp_server_holder(char const *host, char const *port, socket_holder *holder);

    socket_utils::socket_t extract_socket(const socket_holder *wrapper);

    /* Client holder gets saved for future accesses. */
    void save_client_holder(client_register *c_register, client_holder holder);

    /* Delete holder from register.
    *  Once holder gets erased from register, data within holder should not be touched anymore.
    */
    void delete_client_holder(client_register *c_register, client_holder holder);
}

#endif