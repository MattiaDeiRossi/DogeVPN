#ifndef HOLDER_H
#define HOLDER_H

#include <shared_mutex>
#include <optional>
#include <string>
#include <map>

#include <openssl/ssl.h>

#include <socket_utils.h>
#include <tun_utils.h>

namespace holder
{

    const size_t SIZE_512 = 512;
    const size_t SIZE_32 = 32;
    const size_t SIZE_16 = 16;

    const char MESSAGE_SEPARATOR_POINT = '.';
    const char MESSAGE_SEPARATOR_OPEN = '(';
    const char MESSAGE_SEPARATOR_CLOSE = ')';

    struct tun_ip
    {

        char ip[SIZE_32];

        bool operator==(const tun_ip &o) const;
        bool operator<(const tun_ip &o) const;

        tun_ip();
        tun_ip(const char *buffer);
    };

    struct client_holder
    {

        /* This data represents the id for the user that can authenticate to this server and
         * the symmetric key generated for exchanging UDP packets.
         */
        unsigned int session_id;
        unsigned char symmetric_key[SIZE_32];

        /* This value represent the Initial Vector value for every client. This is stored to check the order of the packets.
         */
        unsigned char iv[SIZE_16];
        /* The idea behind this data is that it is the server that is in charge of telling the client
         * that wants to connect what is the IPv4 that they should use to properly configure the TUN device.
         * By doing so the client can freely start the communication without selecting the proper IPv4 to assign to the
         * virtual generated device and at the sime time the server can know to which client send the packet back.
         */
        unsigned int client_tun_ip_id;
        tun_ip client_tun_ip;

        /* After the first message the TCP info is ready to be saved within this holder. For the UDP info,
         * the server need to wait for the first UDP packet related to a specific client.
         */
        socket_utils::tcp_client_info tcp_info;
        socket_utils::udp_client_info udp_info;

        /* The SSL object related to a specific communication within the client and the server. Its deletion is very
         * delicate since there can be situation for which the object is deleted but the structure could still be
         * accessed for whatever reason. The main idea is to keep this structure and the SSL object aligned, that is
         * whenever the SSL object is freed, this structure should not be accessed.
         */
        SSL *ssl;

        std::string to_s();
    };

    struct server_holder
    {
        bool is_tcp;
        socket_utils::socket_t socket;
    };

    struct socket_holder
    {

        enum
        {
            CLIENT_HOLDER,
            SERVER_HOLDER
        } holder_type;

        client_holder c_holder;
        server_holder s_holder;
    };

    struct select_result
    {

        fd_set fdset;
        std::set<socket_utils::socket_t> sockets;
    };

    /* Register of current connected client.
     * Whenever a client connects or disconnects, this object should be properly updated.
     */
    struct client_register
    {

        std::map<unsigned int, client_holder> session_per_holder;
        std::map<tun_ip, unsigned int> tun_ip_per_session;

        tun_utils::ip_pool_t pool;

        std::shared_mutex mutex;

        client_register(tun_utils::ip_pool_t pool);

        /* When calling this method a thread approach may be a better approach since SSL_accept is I/O blocking.
         * When handling a new client there is no need to just create the client socket and return.
         * A dedicated process should handle the process of data exchange without relying on select in the main loop.
         * After a timeout or some error the client socket can be freed along with the thread; this will simplify the whole logic.
         */
        bool register_client_holder(SSL_CTX *ctx, socket_utils::tcp_client_info *info, const char *);

        /* Insert the given client holder within this register. If there is a holder with the same session id,
         * the old one will be deleted (along with the SSL object that is associated to the holder), and the new one will be inserted.
         */
        bool insert_client_holder(client_holder holder);

        bool update_client_holder(client_holder holder);

        /* Erased holder from register if present.
         * Data within holder should not be considered valid anymore.
         */
        void delete_client_holder(client_holder holder, bool free_old_ssl);

        std::optional<client_holder> get_client_holder(unsigned int session_id);

        std::optional<client_holder> get_client_holder(tun_ip ip);

        std::optional<client_holder> find_by_socket(socket_utils::socket_t socket);

        select_result merge_select(std::set<socket_utils::socket_t> set);
    };

    int init_tcp_server_holder(char const *host, char const *port, socket_holder *holder);

    int init_udp_server_holder(char const *host, char const *port, socket_holder *holder);

    socket_utils::socket_t extract_socket(const socket_holder *wrapper);

    holder::socket_holder create_server_holder_or_abort(const char *ip, const char *port, bool is_tcp);
}

#endif