#include "socket_utils.h"

namespace socket_utils {

	int invalid_socket(socket_t socket) {
		return socket < 0;
	}

	void close_socket(socket_t socket) {
		close(socket);
	}

	int bind_server_socket(bool is_tcp, char const *host, char const *port, socket_t *ret_socket) {

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

	    socket_t socket_listen = socket(
	        bind_address->ai_family, 
	        bind_address->ai_socktype,
	        bind_address->ai_protocol
	    );

	    if (invalid_socket(socket_listen)) {
	        freeaddrinfo(bind_address);
	        return -1;
	    }

	    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
	        close_socket(socket_listen);
	        freeaddrinfo(bind_address);
	        return -1;
	    }

	    // Address infos are no longer needed.
	    freeaddrinfo(bind_address);

	    if (is_tcp) {

		    /* Listen put the socket in a state where it listens for new connections.
		    *  The max_connections parameter tells how many connections it is allowed to queue up. 
		    *  If connections become queued up, then the operating system will reject new connections.
		    */
		    if (listen(socket_listen, 15) < 0) {
		        utils::print_error("bind_server_socket: cannot make TCP server listen to new connections\n");
		        close_socket(socket_listen);
		        return -1;
		    }
	    }

	    // Returning correctly created socket.
	    *ret_socket = socket_listen;
	    return 0;
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
	    utils::print("Received bytes from:", 0);
	    utils::print("IP address:", 3);
	    utils::print(address_buffer, 1);
	    utils::print("Port:", 3);
	    utils::print(service_buffer, 1);
	    utils::print("\n", 0);
		utils::println_sep(0);
	}
}