#include "socket_utils.h"

namespace socket_utils {

	int invalid_socket(socket_t socket) {
		return socket < 0;
	}

	void close_socket(socket_t socket) {
		close(socket);
	}

	int create_socket(
		char const *host,
		char const *port,
		bool is_tcp,
		bool is_server,
		socket_t *ret_socket
	) {

		struct addrinfo hints;
	    memset(&hints, 0, sizeof(hints));

	    /* 1. AF_INET:      Looking for IPv4 address
	    *  2. SOCK_STREAM:  Going to use TCP
	    *  3. SOCK_DGRAM:	Going to use UDP
	    */
	    hints.ai_family = AF_INET;
	    hints.ai_socktype = is_tcp ? SOCK_STREAM : SOCK_DGRAM;

		// The variable bind_address will hold the return information from getaddrinfo.
	    struct addrinfo *bind_address;
	    if (getaddrinfo(host, port, &hints, &bind_address) != 0) {
			return -1;
		}

		/* getaddrinfo() returns a list of address structures.
        *  Try each address until we successfully bind(2).
    	*  If socket(2) (or bind(2)) fails, we close the socket and try the next address. 
		*/
		socket_t socket_listen;
		struct addrinfo *ba_p = bind_address;
		while (ba_p) {

			socket_listen = socket(ba_p->ai_family, ba_p->ai_socktype, ba_p->ai_protocol);
			if (invalid_socket(socket_listen)) {
				ba_p = ba_p->ai_next;
				continue;
			}

			int bc_result = is_server ?
				bind(socket_listen, ba_p->ai_addr, ba_p->ai_addrlen) :
				connect(socket_listen, ba_p->ai_addr, ba_p->ai_addrlen);
				
			/* If the connection or binding succeeds, zero is returned.
			*  On success just exit the loop by breaking it.
			*/
			if (bc_result == 0) break;          

			/* Call to bind or connect failed.
			*  On failure just close the socket and continue with the loop.
			*/
			close_socket(socket_listen);
			ba_p = ba_p->ai_next;
		}

		// No longer needed.
		freeaddrinfo(bind_address);

		// No address succeeded.
        if (ba_p == NULL) return -1;


		/* A UDP socket does not need to set itself to a listen state.
		*  Just up to bind. 
		*/
	    if (is_tcp && is_server) {

		    /* Listen put the socket in a state where it listens for new connections.
			*  A backlog argument of 0 may allow the socket to accept connections.
			*  In this case the length of the listen queue may be set to an implementation-defined minimum value.
		    */
		    if (listen(socket_listen, 0) < 0) {
		        utils::print_error("bind_server_socket: cannot make TCP server listen to new connections\n");
		        close_socket(socket_listen);
		        return -1;
		    }
	    }

	    // Returning correctly created socket.
	    *ret_socket = socket_listen;
	    return 0;
	}

	int bind_tcp_server_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, true, true, ret_socket);
	}

	int bind_udp_server_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, false, true, ret_socket);
	}

	int bind_tcp_client_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, true, false, ret_socket);
	}

	int bind_udp_client_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, false, false, ret_socket);
	}

	void log_start_server(bool is_tcp, char const *host, char const *port) {

		utils::println_sep(0);

		if (is_tcp) utils::print("Server can now listen for new TCP connections\n", 0);
		else utils::print("Server can now receive UDP packets\n", 0);

	    utils::print("Server listening:\n", 0);
	    utils::print("IP address:", 3);
	    utils::print(host, 1);
	    utils::print("\n", 0);
	    utils::print("Port:", 3);
	    utils::print(port, 1);
	    utils::print("\n", 0);
	    utils::println_sep(0);
	}

	void log_client_address(struct sockaddr_storage address, socklen_t length) {

    	char address_buffer[256];
	    char service_buffer[256];

	    getnameinfo(
	        (struct sockaddr*) &address, length,
	        address_buffer, sizeof(address_buffer), 
	        service_buffer, sizeof(service_buffer),
	        NI_NUMERICHOST | NI_NUMERICSERV
	    );

	    utils::println_sep(0);
	    utils::print("Received bytes from:\n", 0);
	    utils::print("IP address:", 3);
	    utils::print(address_buffer, 1);
		utils::print("\n", 0);
	    utils::print("Port:", 3);
	    utils::print(service_buffer, 1);
	    utils::print("\n", 0);
		utils::println_sep(0);
	}
}