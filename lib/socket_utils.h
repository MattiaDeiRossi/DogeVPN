#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "utils.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace socket_utils
{

    typedef int socket_t;

    int invalid_socket(socket_t socket);

    void close_socket(socket_t socket);

    /* A TCP server and a UDP server share some common logic when creating a socket.
    *  In particular, both of them should typically perfrom the following operations:
    *   - getaddrinfo()
    *   - socket()
    *   - bind() 
    */
    int bind_server_socket(bool is_tcp, char const *host, char const *port, socket_t *ret_socket);

    void log_start_server(bool is_tcp, char const *host, char const *port);

    void log_client_address(struct sockaddr_storage address, socklen_t length);
}

#endif