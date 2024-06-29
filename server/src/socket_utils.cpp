#include "socket_utils.h"

namespace socket_utils {

	int invalid_socket(socket_t socket) {
		return socket < 0;
	}

	void close_socket(socket_t socket) {
		close(socket);
	}

	int bind_server_socket(bool is_tcp, char const *host, char const *port, socket_t *ret_socket) {

		printf("*** Setting up %s address info ***\n", is_tcp ? "TCP" : "UDP");

	    struct addrinfo hints;
	    memset(&hints, 0, sizeof(struct addrinfo));

	    /* 1. AF_INET:      Looking for IPv4 address
	    *  2. SOCK_STREAM:  Going to use TCP
	    *  3. SOCK_DGRAM:	Going to use UDP
	    *  3. AI_PASSIVE:   Will listen to any available interface
	    */
	    hints.ai_family = AF_INET;
	    hints.ai_socktype = is_tcp ? SOCK_STREAM : SOCK_DGRAM;
	    hints.ai_flags = AI_PASSIVE;

	    // The variable bind_address will hold the return information from getaddrinfo.
	    struct addrinfo *bind_address;
	    getaddrinfo(host, port, &hints, &bind_address);

	    printf("*** Creating %s socket ***\n", is_tcp ? "TCP" : "UDP");

	    socket_t socket_listen = socket(
	        bind_address->ai_family, 
	        bind_address->ai_socktype,
	        bind_address->ai_protocol
	    );

	    if (socket_utils::invalid_socket(socket_listen)) {
	        freeaddrinfo(bind_address);
	        return -1;
	    }

	    printf("*** Binding %s socket ***\n", is_tcp ? "TCP" : "UDP");

	    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
	        socket_utils::close_socket(socket_listen);
	        freeaddrinfo(bind_address);
	        return -1;
	    }

	    // Address infos are no longer needed.
	    freeaddrinfo(bind_address);

	    // Returning correctly created socket.
	    *ret_socket = socket_listen;
	    return 0;

	}
}