#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define CLEAR_MODE "clear_mode"
#define ENCRYPTED_MODE "encrypted_mode"
#define MODE_DETECTION_ERROR 1
#define SOCKET_CREATION_ERROR 2
#define BIND_CREATION_ERROR 3
#define MAX_CONNECTIONS 10
#define SERVER_PORT "8080"

// *** Helper macros ***
// In UNIX platform a socket is just an int, i.e. a file descriptor.
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() (errno)
#define PANIC_EXIT() exit(GET_SOCKET_ERRNO())

typedef int SOCKET;

int is_clear_mode(char const *mode) {
	if (strcmp(mode, CLEAR_MODE) == 0) return 1;
	return 0;
}

int is_enrcypted_mode(char const *mode) {
	if (strcmp(mode, ENCRYPTED_MODE) == 0) return 1;
	return 0;
}

struct addrinfo * get_tcp_address_info(char const *server_port) {

    printf("Setting up TCP address info.\n");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));

    // 1. AF_INET:      Looking for IPv4 address
    // 2. SOCK_STREAM:  Going to use TCP
    // 3. AI_PASSIVE:   Will listen to any available interface
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    // Will hold the return information from getaddrinfo.
    struct addrinfo *bind_address;
    getaddrinfo(0, server_port, &hints, &bind_address);

    return bind_address;
}

/*	The server should start a TCP connection first to handle multiple clients.
*	The schema is the following:
*	getAddrInfo()	-> structure with the proper IP address and port
*	socket()		-> create a socket
*	bind()			-> bound socket to IP address and port	
*	listen() 		-> put the socket in a state for accepting new connections
*	accept() 		-> wait until a client accept a new connection
*	recv()			-> receive data from client
*	send()			-> send data to client
*	close()			-> close TCP connection
*/
int start_clear_doge_vpn() {

	struct addrinfo *bind_address = get_tcp_address_info(SERVER_PORT);

	printf("Creating socket...\n");

	SOCKET socket_listen;
	socket_listen = socket(bind_address->ai_family, bind_address->ai_socktype,bind_address->ai_protocol);

	if (!IS_VALID_SOCKET(socket_listen)) {
		fprintf(stderr, "socket() failed. (%d)\n", GET_SOCKET_ERRNO());
		PANIC_EXIT();
	}

	printf("Binding socket to local address...\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. (%d)\n", GET_SOCKET_ERRNO());
        PANIC_EXIT();
    }

    // Release the address memory.
    freeaddrinfo(bind_address);

    // Listen put the soclet in a state where it listens for new connections.
    // MAX_CONNECTIONS thells how many connections it is allowed to queue up. If
    // MAX_CONNECTION become queued up, then the oerating system will
    // reject new connections.
    printf("Listening...\n");
    if (listen(socket_listen, MAX_CONNECTIONS) < 0) {
    	fprintf(stderr, "listen() failed. (%d)\n", GET_SOCKET_ERRNO());
        PANIC_EXIT();
    }

    // The function accept has a few functions:
    // 1.   Block until a new connection is made
    // 2.   When a connection is made, accept() creates a new socket
    // 3.   While the original socket continues to listen for new connections, the new socket can be 
    //      used to send and receive data
    // 4.   The function will also populate the address info of the client
    printf("Waiting for connection...\n");
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    SOCKET socket_client = accept(socket_listen,
            (struct sockaddr*) &client_address, &client_len);
    if (!IS_VALID_SOCKET(socket_client)) {
        fprintf(stderr, "accept() failed. (%d)\n", GET_SOCKET_ERRNO());
        PANIC_EXIT();
    }


    // At this point a TCP connection has been established to a remote client.
    // Just loggin the client infromation.
    printf("Client is connected... ");
    char address_buffer[100];
    getnameinfo((struct sockaddr*)&client_address,
            client_len, address_buffer, sizeof(address_buffer), 0, 0,
            NI_NUMERICHOST);
    printf("%s\n", address_buffer);

    // The function recv is I/O blocking. This isn't really acceptable when dealing with
    // multiple clients.
    printf("Reading request...\n");
    char request[1024];
    int bytes_received = recv(socket_client, request, 1024, 0);
    printf("Received %d bytes.\n", bytes_received);

    printf("Sending response...\n");
    const char *response =
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Local time is: ";
    int bytes_sent = send(socket_client, response, strlen(response), 0);
    printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(response));

    time_t timer;
    time(&timer);
    char *time_msg = ctime(&timer);
    bytes_sent = send(socket_client, time_msg, strlen(time_msg), 0);
    printf("Sent %d of %d bytes.\n", bytes_sent, (int)strlen(time_msg));

    // Calling close to indicate the client we sent all our data. If we do not close 
    // the connection, the client will juts wait 
    printf("Closing connection...\n");
    CLOSE_SOCKET(socket_client);

    printf("Closing listening socket...\n");
    CLOSE_SOCKET(socket_listen);
	return 0;
}

int start_encrypted_doge_vpn() {
	return 0;
}


int main(int argc, char const *argv[]) {
	
	char const *mode = argv[1];
	int return_val = MODE_DETECTION_ERROR;

	if (is_clear_mode(mode)) {

		// This will be deprecated, but initial setup won't consider encryption using OpenSSL.
		return_val = start_clear_doge_vpn();
	} else if (is_enrcypted_mode(mode)) {

		// The final version.
		return_val = start_encrypted_doge_vpn();
	} else {

		fprintf(stderr, "Failed to detect mode.\n");
	}

	return return_val;
}