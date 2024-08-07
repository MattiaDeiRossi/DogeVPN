#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "utils.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include<optional>
#include<iostream>

namespace socket_utils
{
    typedef int socket_t;

    const socket_t invalid_socket_value = -1;

    struct raw_udp_client_info {

        char address_service[256];

        raw_udp_client_info();
        raw_udp_client_info(struct sockaddr_storage address, socklen_t length);

        bool operator==(const raw_udp_client_info &o) const;
        bool operator<(const raw_udp_client_info &o) const;

        void log();
    };

    struct tcp_client_info {
        socket_t socket;
        socklen_t length;
        struct sockaddr_storage address;

        raw_udp_client_info to_raw_info();  
    };

    struct udp_client_info {

        socklen_t length;
        struct sockaddr_storage address;

        raw_udp_client_info to_raw_info();  
    };
    
    struct recvfrom_result {

        udp_client_info udp_info;
        ssize_t bytes_read;
    };

    int invalid_socket(socket_t socket);

    void close_socket(socket_t socket);

    int bind_tcp_server_socket(char const *host, char const *port, socket_t *ret_socket);

    int bind_udp_server_socket(char const *host, char const *port, socket_t *ret_socket);

    int connect_tcp_client_socket(char const *host, char const *port, socket_t *ret_socket);

    int connect_udp_client_socket(char const *host, char const *port, socket_t *ret_socket);

    socket_t connect_tcp_client_socket_or_abort(char const *host, char const *port);

    socket_t connect_udp_client_socket_or_abort(char const *host, char const *port);

    /* When the TCP socket is ready to accept, call accept_client to create a client socket. */
    tcp_client_info accept_client(socket_t server_socket);

    bool invalid_info(const tcp_client_info *info);

    void log_start_server(bool is_tcp, char const *host, char const *port);

    recvfrom_result recvfrom(socket_t fd, void *buf, size_t n);

    void select_or_throw(socket_t max, fd_set *fd_set_p);
}

#endif