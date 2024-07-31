#include "selector.h"

namespace selector {

    selector_set empty_set() {

        fd_set master;
        FD_ZERO(&master);

        selector_set s_set;
        s_set.socket_set = master;
        s_set.max_socket = 0;

        return s_set;
    }

    void add(selector_set *set, socket_utils::socket_t socket) {

        FD_SET(socket, &(set->socket_set));

        socket_utils::socket_t current = set->max_socket;
        set->sockets.insert(socket);
        set->max_socket = socket > current ? socket : current;
    }

    void remove(selector_set *set, socket_utils::socket_t socket) {

        FD_CLR(socket, &(set->socket_set));
        set->sockets.erase(socket);

        if (socket == set->max_socket) {
            
            int max = -1;
            for (auto i : set->sockets) {
                if (i > max) max = i;
            }

            set->max_socket = max;
        }
    }

    int wait_select(const selector_set *s_set, fd_set *reads) {
        return select(s_set->max_socket + 1, reads, 0, 0, 0);
    }

    bool is_set(const fd_set *reads, socket_utils::socket_t socket) {
        return FD_ISSET(socket, reads) != 0 ? true : false;
    }
}
