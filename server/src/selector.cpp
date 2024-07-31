#include "selector.h"

namespace selector {

    selector_set create_set(std::vector<socket_utils::socket_t> sockets) {

        fd_set master;
        FD_ZERO(&master);

        selector_set s_set;

        socket_utils::socket_t max_socket = 0;

        for (auto socket : sockets) {
            FD_SET(socket, &master);
            max_socket = socket > max_socket ? socket : max_socket;
            s_set.socket_set.insert(socket);
        }

        s_set.socket_fd_set = master;
        s_set.max_socket = max_socket;

        return s_set;
    }

    void add(selector_set *set, socket_utils::socket_t socket) {

        FD_SET(socket, &(set->socket_fd_set));

        socket_utils::socket_t current = set->max_socket;
        set->max_socket = socket > current ? socket : current;
        set->socket_set.insert(socket);
    }

    void remove(selector_set *set, socket_utils::socket_t socket) {

        FD_CLR(socket, &(set->socket_fd_set));
        set->socket_set.erase(socket);

        if (socket == set->max_socket) {
            
            int max = 0;
            for (auto i : set->socket_set) {
                if (i > max) max = i;
            }

            set->max_socket = max;
        }
    }

    int wait_select(const selector_set *s_set, fd_set *reads) {
        *reads = s_set->socket_fd_set;
        return select(s_set->max_socket + 1, reads, 0, 0, 0);
    }

    fd_set wait_select_or_abort(const selector_set *s_set) {

        fd_set reads;
        if (selector::wait_select(s_set, &reads) == -1) {
            fprintf(stderr, "wait_select_or_abort: select failed\n");
            exit(EXIT_FAILURE);
        }

        return reads;
    }

    bool is_set(const fd_set *reads, socket_utils::socket_t socket) {
        return FD_ISSET(socket, reads) != 0 ? true : false;
    }
}
