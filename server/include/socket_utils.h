#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "standards.h"
#include "data_structures.h"

namespace socket_utils
{

    int invalid_socket(socket_t socket);

    void close_socket(socket_t socket);
}

#endif