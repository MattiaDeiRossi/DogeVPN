#ifndef HOLDER_H
#define HOLDER_H

#include <map>
#include <shared_mutex>
#include <mutex>
#include <optional>
#include <stdlib.h>
#include "socket_utils.h"
#include "ssl_utils.h"
#include "tun_utils.h"
#include "vpn_data_utils.h"

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
        unsigned char symmetric_key[SIZE_32];

        /*
        */
        unsigned int client_tun_ip_id;
        tun_ip client_tun_ip;

        /*
        */
        socket_utils::tcp_client_info tcp_info;
        socket_utils::udp_client_info udp_info;

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

        /* Associations. */
        std::map<unsigned int, client_holder> session_per_holder;
        std::map<tun_ip, unsigned int> tun_ip_per_session;

        /* Pool handled by this register. */
        tun_utils::ip_pool_t pool;
        
        /* This register must be pretected with mutex. */
        std::shared_mutex mutex;
    };

    void create_client_register_with_c_pool(unsigned char third_octet, client_register *result);

    int init_tcp_server_holder(char const *host, char const *port, socket_holder *holder);

    /* When calling this method a thread approach may be a better approach since SSL_accept is I/O blocking.
    *  When handling a new client there is no need to just create the client socket and return.
    *  A dedicated process should handle the process of data exchange without relying on select in the main loop.
    *  After a timeout or some error the client socket can be freed along with the thread; this will simplify the whole logic.
    */
    int register_client_holder(
        client_register *c_register,
        SSL_CTX *ctx,
        socket_utils::tcp_client_info *info
    );

    int init_udp_server_holder(char const *host, char const *port, socket_holder *holder);

    socket_utils::socket_t extract_socket(const socket_holder *wrapper);

    void save_client_holder(client_register *c_register, client_holder holder);

    /* Once holder gets erased from register, data within holder should not be touched anymore. */
    void delete_client_holder(client_register *c_register, client_holder holder);

    int extract_client_key(
        client_register *c_register,
        unsigned int session_id,
        unsigned char *symmetric_key
    );

    holder::socket_holder create_server_holder_or_abort(const char *ip, const char *port, bool is_tcp);
}

#endif