#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "utils.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace socket_utils
{
    typedef int socket_t;

    const socket_t invalid_socket_value = -1;

    int invalid_socket(socket_t socket);

    void close_socket(socket_t socket);

    int bind_tcp_server_socket(char const *host, char const *port, socket_t *ret_socket);

    int bind_udp_server_socket(char const *host, char const *port, socket_t *ret_socket);

    int bind_tcp_client_socket(char const *host, char const *port, socket_t *ret_socket);

    int bind_udp_client_socket(char const *host, char const *port, socket_t *ret_socket);

    void log_start_server(bool is_tcp, char const *host, char const *port);

    void log_client_address(struct sockaddr_storage address, socklen_t length);
}

#endif