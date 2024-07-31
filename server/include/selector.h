#ifndef SELECTOR_H
#define SELECTOR_H

#include <sys/select.h>
#include <stdlib.h>
#include <set>
#include <vector>
#include "socket_utils.h"

namespace selector {

    struct selector_set {
        fd_set socket_fd_set;
        socket_utils::socket_t max_socket;
        std::set<socket_utils::socket_t> socket_set;
    };

    selector_set create_set(std::vector<socket_utils::socket_t> sockets);

    void add(selector_set *set, socket_utils::socket_t socket);

    void remove(selector_set *set, socket_utils::socket_t socket);

    int wait_select(const selector_set *s_set, fd_set *reads);

    fd_set wait_select_or_abort(const selector_set *s_set);

    bool is_set(const fd_set *reads, socket_utils::socket_t socket);
}

#endif