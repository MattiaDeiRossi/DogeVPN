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

	int connect_tcp_client_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, true, false, ret_socket);
	}

	int connect_udp_client_socket(char const *host, char const *port, socket_t *ret_socket) {
		return create_socket(host, port, false, false, ret_socket);
	}

	socket_t connect_tcp_client_socket_or_abort(char const *host, char const *port) {

		socket_t socket;
		if (connect_tcp_client_socket(host, port, &socket) == -1) {
			fprintf(stderr, "connect_tcp_client_socket_or_abort: cannot connect tcp client socket\n");
			exit(EXIT_FAILURE);
		}

		return socket;
	}

    socket_t connect_udp_client_socket_or_abort(char const *host, char const *port) {

		socket_t socket;
		if (connect_udp_client_socket(host, port, &socket) == -1) {
			fprintf(stderr, "connect_udp_client_socket_or_abort: cannot connect udp client socket\n");
			exit(EXIT_FAILURE);
		}

		return socket;
	}

	tcp_client_info accept_client(socket_t server_socket) {

		struct sockaddr_storage client_address;
        socklen_t client_length = sizeof(client_address);

		socket_utils::socket_t client_socket = accept(
			server_socket,
			(struct sockaddr*) &client_address,
			&client_length
		);

		tcp_client_info info;
		info.socket = client_socket;
		info.address = client_address;
		info.length = client_length;

		return info;
	}

    bool invalid_info(const tcp_client_info *info) {
		return socket_utils::invalid_socket(info->socket);
	}

	void log_start_server(bool is_tcp, char const *host, char const *port) {

		if (is_tcp) utils::print("Server can now listen for new TCP connections\n", 0);
		else utils::print("Server can now receive UDP packets\n", 0);

	    utils::print("Server listening:\n", 0);
	    utils::print("IP address:", 3);
	    utils::print(host, 1);
	    utils::print("\n", 0);
	    utils::print("Port:", 3);
	    utils::print(port, 1);
	    utils::print("\n", 0);
	}

	recvfrom_result recvfrom(socket_t fd, void *buf, size_t n) {

		struct sockaddr_storage client_address;
		socklen_t client_len = sizeof(client_address);
		ssize_t bytes_read = recvfrom(fd, buf, n, 0, (struct sockaddr *) &client_address, &client_len);
		
		udp_client_info udp_info;
		udp_info.address = client_address;
		udp_info.length = client_len;

		recvfrom_result result;
		result.udp_info = udp_info;
		result.bytes_read = bytes_read;

		return result;
	}

	raw_udp_client_info::raw_udp_client_info() {
		bzero(address_service, 256);
	}

	void raw_udp_client_info::log() {
		std::cout << 
			"Received packet from:\n" << 
			address_service << 
			"\n";
	}

	raw_udp_client_info udp_client_info::to_raw_info() {

		raw_udp_client_info raw_info;

		char address_buffer[128];
	    char service_buffer[128];

	    getnameinfo(
	        (struct sockaddr*) &address, length,
	        address_buffer, sizeof(address_buffer), 
	        service_buffer, sizeof(service_buffer),
	        NI_NUMERICHOST | NI_NUMERICSERV
	    );

		size_t index = 0;
		char *a_ptr = address_buffer;
		char *s_ptr = service_buffer;
		
		while (*a_ptr) {
			raw_info.address_service[index++] = *a_ptr;
			a_ptr++;
		}

		raw_info.address_service[index++] = ':';

		while (*s_ptr) {
			raw_info.address_service[index++] = *s_ptr;
			s_ptr++;
		}

		return raw_info;
	}

	bool raw_udp_client_info::operator==(const raw_udp_client_info &o) const {
        return strncmp(address_service, o.address_service, 256) == 0 ? true : false;
    }

	bool raw_udp_client_info::operator<(const raw_udp_client_info &o) const {
        return strncmp(address_service, o.address_service, 256) < 0 ? true : false;
    }
}