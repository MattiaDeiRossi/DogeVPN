#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "standards.h"
#include "data_structures.h"

namespace socket_utils
{

    int invalid_socket(socket_t socket);

    void close_socket(socket_t socket);

    /* A TCP server and a UDP server share some common logic when creating a socket.
    *  In particular, both of them should typically perfrom the following operations:
    *   - getaddrinfo()
    *   - socket()
    *   - bind() 
    */
    int bind_server_socket(bool is_tcp, char const *host, char const *port, socket_t *ret_socket);
}

#endif