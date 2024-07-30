#ifndef SELECTOR_H
#define SELECTOR_H

#include <sys/select.h>
#include <set>
#include "socket_utils.h"

namespace selector {

    struct selector_set {
        fd_set socket_set;
        socket_utils::socket_t max_socket;
        std::set<socket_utils::socket_t> sockets;
    };

    selector_set empty_set();

    void add(selector_set *set, socket_utils::socket_t socket);

    void remove(selector_set *set, socket_utils::socket_t socket);

    int wait_select(const selector_set *s_set, fd_set *reads);

    bool is_set(const fd_set *reads, socket_utils::socket_t socket);
}

#endif